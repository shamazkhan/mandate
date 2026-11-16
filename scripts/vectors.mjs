// Generates spec/test-vectors/v0.1.json deterministically (Ed25519 signatures are deterministic).
import { writeFileSync } from 'node:fs';
import { keyFromSeed, issueMandate, signRequest, publicOf } from '../dist/index.js';
import { parseSignature } from '../dist/core/signature.js';
import { signatureBase } from '../dist/core/signature.js';

const seed = (n) => new Uint8Array(32).fill(n);
const issuer = keyFromSeed('issuer', seed(1));
const agent = keyFromSeed('agent', seed(2));
const policy = { instruments: ['us_equity', 'etf'], symbols: { deny: ['GME'] }, max_order_notional: 25000, require_approval: { above_notional: 10000 }, exits: 'always_allow', currency: 'USD' };
const mandate = issueMandate({ issuer, agent: agent.kid, sub: 'acct_8341@example-broker', policy, iat: 1763300000, ttl: 2592000, mid: 'mdt_AAAAAAAAAAAAAAAAAAAAAA', aud: ['broker.example'] });
const url = 'https://broker.example/v2/orders';
const body = '{"symbol":"MSFT","qty":"10","side":"buy","type":"market","time_in_force":"day"}';
const headers = signRequest({ method: 'POST', url, body, mandate, key: agent, created: 1763300100, ttl: 60, nonce: 'bm9uY2Utdi0wLjEtdGVzdA' });
const p = parseSignature({ method: 'POST', url, headers, body });
const base = signatureBase(p.components, p.paramsRaw, 'POST', url, (h) => ({ 'content-digest': headers['Content-Digest'], mandate })[h]);

const out = {
  description: 'Mandate Protocol draft 0.1 test vector. Keys are derived from fixed seeds and MUST NOT be used for anything else.',
  keys: {
    issuer: { seed_hex: Buffer.from(seed(1)).toString('hex'), kid: issuer.kid, public_jwk: publicOf(issuer.jwk) },
    agent: { seed_hex: Buffer.from(seed(2)).toString('hex'), kid: agent.kid, public_jwk: publicOf(agent.jwk) },
  },
  mandate: { token: mandate, policy },
  request: { method: 'POST', url, body, verify_at: 1763300110, verifier_id: 'broker.example' },
  signature_base: base,
  headers,
  expected: { decision: 'allow', account: { equity: 100000, positions: {}, prices: { MSFT: 400 } } },
};
writeFileSync('spec/test-vectors/v0.1.json', JSON.stringify(out, null, 2) + '\n');
console.log('wrote spec/test-vectors/v0.1.json');
console.log(JSON.stringify({ issuer: issuer.kid, agent: agent.kid }, null, 1));
