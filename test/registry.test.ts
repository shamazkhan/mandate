import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createRegistryServer } from '../src/registry/server.js';
import { RegistryClient, proofFor } from '../src/registry/client.js';
import { generateKey } from '../src/core/keys.js';
import { issueMandate } from '../src/core/mandate.js';
import { createVerifier } from '../src/verifier/index.js';
import { alpacaAdapter } from '../src/adapters/index.js';
import { signRequest } from '../src/core/signature.js';
import { ACCOUNT, URL_ORDERS } from './helpers.js';

async function start() {
  const { server, store } = createRegistryServer({ adminToken: 'op-secret' });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { server, store, url };
}

test('registry: agents self-register with proof; issuers need the operator', async (t) => {
  const { server, url } = await start();
  t.after(() => server.close());
  const agent = generateKey('agent');
  const pub = new RegistryClient({ url, pollInterval: 0 });
  const rec = await pub.register(agent, { name: 'bot', operator: { name: 'Acme' } });
  assert.equal(rec.kid, agent.kid);
  assert.equal(rec.assurance, 'basic');
  await assert.rejects(pub.register(agent), /409/);
  await assert.rejects(pub.register(generateKey('issuer')), /403/);
  const op = new RegistryClient({ url, adminToken: 'op-secret', pollInterval: 0 });
  const issuer = generateKey('issuer');
  assert.equal((await op.register(issuer)).type, 'issuer');
  assert.equal((await op.setAssurance(agent.kid, 'verified')).assurance, 'verified');
  await assert.rejects(pub.setAssurance(agent.kid, 'preflight'), /403/);
  const wk = await (await fetch(`${url}/.well-known/mandate-registry`)).json();
  assert.equal((wk as any).protocol, 'mandate/0.1');
});

test('registry: proofs must be signed by the key and fresh', async (t) => {
  const { server, url } = await start();
  t.after(() => server.close());
  const agent = generateKey('agent');
  const other = generateKey('agent');
  const post = (body: unknown) => fetch(`${url}/v0/keys`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: agent.jwk.x };
  assert.equal((await post({ type: 'agent', jwk })).status, 401);
  assert.equal((await post({ type: 'agent', jwk, proof: proofFor(other, { op: 'register', kid: agent.kid }) })).status, 401);
  const stale = proofFor(agent, { op: 'register', kid: agent.kid });
  assert.equal((await post({ type: 'agent', jwk, proof: { ...stale, ts: stale.ts - 1000 } })).status, 401);
  assert.equal((await post({ type: 'agent', jwk, proof: proofFor(agent, { op: 'register', kid: agent.kid }) })).status, 201);
});

test('kill switch: revoking in the registry stops the agent at the verifier', async (t) => {
  const { server, url } = await start();
  t.after(() => server.close());
  const op = new RegistryClient({ url, adminToken: 'op-secret', pollInterval: 0 });
  const issuer = generateKey('issuer');
  const agent = generateKey('agent');
  await op.register(issuer);
  await op.register(agent);
  const mandate = issueMandate({ issuer, agent: agent.kid, sub: 'acct', policy: { max_order_notional: 10_000 } });
  const resolver = new RegistryClient({ url, ttl: 60, pollInterval: 0.001 });
  const verifier = createVerifier({ registry: resolver, adapter: alpacaAdapter(), context: () => ACCOUNT });
  const send = () => {
    const body = JSON.stringify({ symbol: 'MSFT', qty: '1', side: 'buy', type: 'market' });
    return verifier.verify({ method: 'POST', url: URL_ORDERS, headers: signRequest({ method: 'POST', url: URL_ORDERS, body, mandate, key: agent }) as any, body });
  };
  assert.equal((await send()).decision, 'allow');
  await new RegistryClient({ url, pollInterval: 0 }).revokeKey(agent);
  await new Promise((r) => setTimeout(r, 10));
  const r = await send();
  assert.deepEqual(r.reasons.map((x) => x.code), ['agent_revoked']);
});

test('mandate revocation by its issuer', async (t) => {
  const { server, url } = await start();
  t.after(() => server.close());
  const op = new RegistryClient({ url, adminToken: 'op-secret', pollInterval: 0 });
  const issuer = generateKey('issuer');
  await op.register(issuer);
  const pub = new RegistryClient({ url, pollInterval: 0 });
  await assert.rejects(pub.revokeMandate('mdt_aaaaaaaaaaaaaaaaaaaaaa', generateKey('issuer')), /401/);
  await pub.revokeMandate('mdt_aaaaaaaaaaaaaaaaaaaaaa', issuer);
  assert.ok(await pub.isMandateRevoked('mdt_aaaaaaaaaaaaaaaaaaaaaa'));
  assert.ok(!(await pub.isMandateRevoked('mdt_bbbbbbbbbbbbbbbbbbbbbb')));
});

test('client rejects a registry record whose key does not match the kid', async () => {
  const real = generateKey('agent');
  const swapped = generateKey('agent');
  const fake = (async () => new Response(JSON.stringify({ kid: real.kid, type: 'agent', jwk: { kty: 'OKP', crv: 'Ed25519', x: swapped.jwk.x }, status: 'active', assurance: 'basic', created_at: 0 }), { status: 200 })) as typeof fetch;
  const c = new RegistryClient({ url: 'http://evil', fetch: fake, pollInterval: 0 });
  assert.equal(await c.getKey(real.kid), null);
});
