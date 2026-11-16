import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keyFromSeed, publicOf } from '../src/core/keys.js';
import { issueMandate } from '../src/core/mandate.js';
import { signRequest } from '../src/core/signature.js';
import { StaticRegistry } from '../src/registry/static.js';
import { createVerifier } from '../src/verifier/index.js';
import { alpacaAdapter } from '../src/adapters/index.js';

const v = JSON.parse(readFileSync(new URL('../../spec/test-vectors/v0.1.json', import.meta.url), 'utf8'));

test('conformance vector: keys, mandate and signature reproduce exactly', () => {
  const issuer = keyFromSeed('issuer', Buffer.from(v.keys.issuer.seed_hex, 'hex'));
  const agent = keyFromSeed('agent', Buffer.from(v.keys.agent.seed_hex, 'hex'));
  assert.equal(issuer.kid, v.keys.issuer.kid);
  assert.deepEqual(publicOf(agent.jwk), v.keys.agent.public_jwk);
  const mandate = issueMandate({ issuer, agent: agent.kid, sub: 'acct_8341@example-broker', policy: v.mandate.policy, iat: 1763300000, ttl: 2592000, mid: 'mdt_AAAAAAAAAAAAAAAAAAAAAA', aud: ['broker.example'] });
  assert.equal(mandate, v.mandate.token);
  const h = signRequest({ method: 'POST', url: v.request.url, body: v.request.body, mandate, key: agent, created: 1763300100, ttl: 60, nonce: 'bm9uY2Utdi0wLjEtdGVzdA' });
  assert.deepEqual(h, v.headers);
});

test('conformance vector: a verifier with only public keys allows it', async () => {
  const registry = new StaticRegistry();
  registry.put({ kid: v.keys.issuer.kid, type: 'issuer', jwk: v.keys.issuer.public_jwk, status: 'active', assurance: 'basic', created_at: 0 });
  registry.put({ kid: v.keys.agent.kid, type: 'agent', jwk: v.keys.agent.public_jwk, status: 'active', assurance: 'basic', created_at: 0 });
  const verifier = createVerifier({ registry, id: v.request.verifier_id, adapter: alpacaAdapter(), now: () => v.request.verify_at, context: () => v.expected.account });
  const r = await verifier.verify({ method: v.request.method, url: v.request.url, headers: v.headers, body: v.request.body });
  assert.equal(r.decision, v.expected.decision);
});
