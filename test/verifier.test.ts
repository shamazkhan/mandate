import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setup, codes, URL_ORDERS } from './helpers.js';
import { generateKey } from '../src/core/keys.js';
import { issueMandate } from '../src/core/mandate.js';
import { signRequest } from '../src/core/signature.js';
import { verifyChain, EvidenceLog } from '../src/evidence/index.js';
import { nowSeconds } from '../src/core/encoding.js';

test('allowed order produces an evidence entry with agent, mandate and order', async () => {
  const { verifier, order, agent } = setup();
  const r = await verifier.verify(order({ symbol: 'MSFT', qty: '10', side: 'buy' }));
  assert.equal(r.decision, 'allow');
  assert.equal(r.evidence.agent, agent.kid);
  assert.equal(r.evidence.sub, 'acct_1');
  assert.equal(r.evidence.order?.symbol, 'MSFT');
  assert.equal(r.evidence.operator, 'Acme');
});

test('unsigned and malformed requests are denied', async () => {
  const { verifier } = setup();
  assert.deepEqual(codes(await verifier.verify({ method: 'POST', url: URL_ORDERS, headers: {}, body: '{}' })), ['unsigned']);
  assert.deepEqual(codes(await verifier.verify({ method: 'POST', url: URL_ORDERS, headers: { 'signature-input': 'x', signature: 'y' }, body: '{}' })), ['unsigned']);
});

test('tampered body, URL and method are caught', async () => {
  const { verifier, order } = setup();
  const req = order({ symbol: 'MSFT', qty: '1', side: 'buy' });
  assert.deepEqual(codes(await verifier.verify({ ...req, body: req.body.replace('"1"', '"999"') })), ['digest_mismatch']);
  const req2 = order({ symbol: 'MSFT', qty: '1', side: 'buy' });
  assert.deepEqual(codes(await verifier.verify({ ...req2, url: 'https://broker.example/v2/orders?evil=1' })), ['signature_invalid']);
  const req3 = order({ symbol: 'MSFT', qty: '1', side: 'buy' });
  assert.deepEqual(codes(await verifier.verify({ ...req3, method: 'PUT' })), ['signature_invalid']);
});

test('replay is denied; a forged request cannot burn a nonce', async () => {
  const { verifier, order } = setup();
  const req = order({ symbol: 'MSFT', qty: '1', side: 'buy' });
  const forged = { ...req, headers: { ...req.headers, Signature: 'mandate=:' + Buffer.alloc(64).toString('base64') + ':' } };
  assert.deepEqual(codes(await verifier.verify(forged)), ['signature_invalid']);
  assert.equal((await verifier.verify(req)).decision, 'allow');
  assert.deepEqual(codes(await verifier.verify(req)), ['replay']);
});

test('signature freshness uses created and expires', async () => {
  const { verifier, agent, mandate } = setup(undefined, { now: () => nowSeconds() + 3600 });
  const body = JSON.stringify({ symbol: 'MSFT', qty: '1', side: 'buy', type: 'market' });
  const h = signRequest({ method: 'POST', url: URL_ORDERS, body, mandate, key: agent });
  assert.deepEqual(codes(await verifier.verify({ method: 'POST', url: URL_ORDERS, headers: h as any, body })), ['signature_expired']);
  const future = signRequest({ method: 'POST', url: URL_ORDERS, body, mandate, key: agent, created: nowSeconds() + 7200 });
  assert.deepEqual(codes(await verifier.verify({ method: 'POST', url: URL_ORDERS, headers: future as any, body })), ['signature_not_yet_valid']);
});

test('unknown, revoked and under-assured agents are denied', async () => {
  const s = setup();
  const stranger = generateKey('agent');
  assert.deepEqual(codes(await s.verifier.verify(s.order({ symbol: 'MSFT', qty: '1', side: 'buy' }, stranger))), ['agent_unknown']);
  const s2 = setup(undefined, { minAssurance: 'verified' });
  assert.deepEqual(codes(await s2.verifier.verify(s2.order({ symbol: 'MSFT', qty: '1', side: 'buy' }))), ['assurance_insufficient']);
  s2.registry.setAssurance(s2.agent.kid, 'verified');
  assert.equal((await s2.verifier.verify(s2.order({ symbol: 'MSFT', qty: '1', side: 'buy' }))).decision, 'allow');
  s.registry.revokeKey(s.agent.kid);
  assert.deepEqual(codes(await s.verifier.verify(s.order({ symbol: 'MSFT', qty: '1', side: 'buy' }))), ['agent_revoked']);
});

test('mandate checks: missing, other agent, other issuer, audience, revoked, expired', async () => {
  const s = setup();
  const req = s.order({ symbol: 'MSFT', qty: '1', side: 'buy' });
  const noMandate = signRequest({ method: 'POST', url: URL_ORDERS, body: req.body, mandate: '', key: s.agent });
  assert.ok(['mandate_missing', 'mandate_invalid'].includes(codes(await s.verifier.verify({ ...req, headers: noMandate as any }))[0]!));

  const other = generateKey('agent');
  s.registry.add(other);
  assert.deepEqual(codes(await s.verifier.verify(s.order({ symbol: 'MSFT', qty: '1', side: 'buy' }, other))), ['mandate_agent_mismatch']);

  const rogueIssuer = generateKey('issuer');
  const fake = issueMandate({ issuer: rogueIssuer, agent: s.agent.kid, sub: 'acct_1', policy: {} });
  assert.deepEqual(codes(await s.verifier.verify(s.order({ symbol: 'MSFT', qty: '1', side: 'buy' }, s.agent, URL_ORDERS, fake))), ['issuer_unknown']);
  s.registry.add(rogueIssuer);
  const t = setup(undefined, { trustedIssuers: ['someone-else'] });
  assert.deepEqual(codes(await t.verifier.verify(t.order({ symbol: 'MSFT', qty: '1', side: 'buy' }))), ['issuer_untrusted']);

  const a = setup(undefined, {}, { aud: ['other-broker'] });
  assert.deepEqual(codes(await a.verifier.verify(a.order({ symbol: 'MSFT', qty: '1', side: 'buy' }))), ['mandate_audience_mismatch']);

  const mid = (await s.verifier.verify(s.order({ symbol: 'MSFT', qty: '1', side: 'buy' }))).mandate!.mid;
  s.registry.revokeMandate(mid);
  assert.deepEqual(codes(await s.verifier.verify(s.order({ symbol: 'AAPL', qty: '1', side: 'sell' }))), ['mandate_revoked']);

  const e = setup(undefined, {}, { iat: nowSeconds() - 7200, ttl: 3600 });
  assert.deepEqual(codes(await e.verifier.verify(e.order({ symbol: 'MSFT', qty: '1', side: 'buy' }))), ['mandate_expired']);
  assert.deepEqual(codes(await e.verifier.verify(e.order({ symbol: 'AAPL', qty: '10', side: 'sell' }))), ['exit_always_allowed']);
});

test('daily notional accumulates only allowed orders', async () => {
  const { verifier, order } = setup({ max_daily_notional: 10_000 });
  assert.equal((await verifier.verify(order({ symbol: 'MSFT', qty: '20', side: 'buy' }))).decision, 'allow');
  assert.deepEqual(codes(await verifier.verify(order({ symbol: 'MSFT', qty: '6', side: 'buy' }))), ['daily_notional_exceeded']);
  assert.equal((await verifier.verify(order({ symbol: 'MSFT', qty: '5', side: 'buy' }))).decision, 'allow');
});

test('non-order requests are allowed after identity checks; unreadable orders are denied', async () => {
  const s = setup();
  const h = signRequest({ method: 'GET', url: 'https://broker.example/v2/positions', mandate: s.mandate, key: s.agent });
  const r = await s.verifier.verify({ method: 'GET', url: 'https://broker.example/v2/positions', headers: h as any });
  assert.equal(r.decision, 'allow');
  assert.deepEqual(codes(r), ['not_an_order']);
  assert.deepEqual(codes(await s.verifier.verify(s.order({ symbol: 'MSFT', side: 'buy' }))), ['order_unreadable']);
  assert.deepEqual(codes(await s.verifier.verify(s.order({ symbol: 'MSFT', qty: '1', side: 'buy', order_class: 'mleg' }))), ['order_unreadable']);
});

test('evidence chain is intact and detects tampering, signed entries verify', async () => {
  const signer = generateKey('verifier');
  const evidence = new EvidenceLog({ signer });
  const { verifier, order, mandate } = setup(undefined, { evidence });
  await verifier.verify(order({ symbol: 'MSFT', qty: '1', side: 'buy' }));
  await verifier.verify(order({ symbol: 'GME', qty: '1', side: 'buy' }));
  await verifier.verify(order({ symbol: 'TSLA', qty: '100', side: 'buy' }));
  assert.ok(verifyChain(evidence.entries, signer.jwk).ok);
  const copy = evidence.entries.map((e) => ({ ...e }));
  copy[1]!.decision = 'allow';
  assert.equal(verifyChain(copy).error, 'entry 2 was modified');
  assert.equal(verifyChain([copy[0]!, copy[2]!]).ok, false);
  assert.equal(verifyChain(evidence.entries, generateKey('verifier').jwk).ok, false);
  assert.ok(!JSON.stringify(evidence.entries).includes(mandate.split('.')[2]!), 'evidence must not contain the mandate token');
});
