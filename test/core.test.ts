import { test } from 'node:test';
import assert from 'node:assert/strict';
import { thumbprint, generateKey, keyFromSeed, signBytes, verifyBytes, parseKeyFile } from '../src/core/keys.js';
import { canonicalJson } from '../src/core/encoding.js';
import { contentDigest, checkContentDigest } from '../src/core/digest.js';
import { parseDictionary, serializeInnerList } from '../src/core/structured.js';
import { signRequest, parseSignature, verifySignature } from '../src/core/signature.js';
import { issueMandate, decodeMandate, verifyMandateSignature } from '../src/core/mandate.js';
import { b64u } from '../src/core/encoding.js';

test('RFC 8037 A.3: JWK thumbprint of the Ed25519 example key', () => {
  assert.equal(thumbprint({ kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' }), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('RFC 8037 A.1: key from seed matches the published public key', () => {
  const k = keyFromSeed('agent', b64u.decode('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A'));
  assert.equal(k.jwk.x, '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo');
});

test('RFC 8032: Ed25519 sign and verify, wrong data fails', () => {
  const k = generateKey('agent');
  const sig = signBytes(k.jwk, 'hello');
  assert.ok(verifyBytes(k.jwk, 'hello', sig));
  assert.ok(!verifyBytes(k.jwk, 'hellO', sig));
  assert.ok(!verifyBytes(k.jwk, 'hello', sig.subarray(0, 63)));
});

test('key files round-trip and reject a mismatched kid', () => {
  const k = generateKey('issuer');
  assert.equal(parseKeyFile(JSON.stringify(k)).kid, k.kid);
  assert.throws(() => parseKeyFile(JSON.stringify({ ...k, kid: generateKey('issuer').kid })), /kid does not match/);
});

test('canonical JSON sorts keys and drops undefined', () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, 'x'], c: undefined, d: { z: 1, y: 2 } }), '{"a":[true,null,"x"],"b":1,"d":{"y":2,"z":1}}');
  assert.throws(() => canonicalJson({ a: Infinity }));
});

test('RFC 9530: Content-Digest', () => {
  // RFC 9530 B.1: {"hello": "world"}\n
  assert.equal(contentDigest('{"hello": "world"}\n'), 'sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:');
  assert.ok(checkContentDigest(contentDigest('abc'), 'abc'));
  assert.ok(!checkContentDigest(contentDigest('abc'), 'abd'));
  assert.ok(!checkContentDigest('garbage', 'abc'));
});

test('structured fields: parse what we serialise, keep raw member text', () => {
  const raw = serializeInnerList(['@method', 'mandate'], [['created', 1], ['keyid', 'k"1'], ['alg', 'ed25519']]);
  const d = parseDictionary(`sig1=:AAEC:, mandate=${raw}`);
  const m = d.get('mandate')!;
  assert.equal(m.kind, 'inner');
  assert.equal(m.raw, raw);
  assert.equal(m.kind === 'inner' && m.params.get('keyid'), 'k"1');
  assert.throws(() => parseDictionary('a=(unterminated'));
});

test('signature: round trip, and any change to method, URL, body or mandate breaks it', () => {
  const agent = generateKey('agent');
  const body = '{"symbol":"MSFT"}';
  const url = 'https://b.example/v2/orders?x=1';
  const h = signRequest({ method: 'post', url, body, mandate: 'tok', key: agent });
  const req = { method: 'POST', url, headers: h as unknown as Record<string, string>, body };
  const p = parseSignature(req)!;
  assert.deepEqual(p.components, ['@method', '@target-uri', 'content-digest', 'mandate']);
  assert.equal(p.keyid, agent.kid);
  assert.ok(verifySignature(req, p, agent.jwk));
  assert.ok(!verifySignature({ ...req, method: 'PUT' }, p, agent.jwk));
  assert.ok(!verifySignature({ ...req, url: url + '2' }, p, agent.jwk));
  assert.ok(!verifySignature({ ...req, headers: { ...req.headers, Mandate: 'other' } }, p, agent.jwk));
  assert.ok(!verifySignature({ ...req, headers: { ...req.headers, 'Content-Digest': contentDigest('x') } }, p, agent.jwk));
  assert.ok(!verifySignature(req, p, generateKey('agent').jwk));
});

test('signature: requests without a body do not cover content-digest', () => {
  const agent = generateKey('agent');
  const h = signRequest({ method: 'GET', url: 'https://b.example/v2/positions', mandate: 't', key: agent });
  assert.equal(h['Content-Digest'], undefined);
  assert.match(h['Signature-Input'], /^mandate=\("@method" "@target-uri" "mandate"\);created=\d+;expires=\d+;keyid="[\w-]+";alg="ed25519";nonce="[\w-]+";tag="mandate\/0\.1"$/);
});

test('mandate: issue, decode, verify; tampering and wrong issuer fail', () => {
  const issuer = generateKey('issuer');
  const t = issueMandate({ issuer, agent: 'agentkid', sub: 'acct', policy: { max_order_notional: 1 }, ttl: 60, aud: ['b'] });
  const d = decodeMandate(t);
  assert.equal(d.header.typ, 'mandate+jws');
  assert.equal(d.payload.exp - d.payload.iat, 60);
  assert.ok(verifyMandateSignature(d, issuer.jwk));
  assert.ok(!verifyMandateSignature(d, generateKey('issuer').jwk));
  const [h, p, s] = t.split('.');
  const evil = JSON.parse(b64u.decode(p!).toString());
  evil.policy.max_order_notional = 1e9;
  assert.ok(!verifyMandateSignature(decodeMandate(`${h}.${b64u.encode(JSON.stringify(evil))}.${s}`), issuer.jwk));
  assert.throws(() => decodeMandate('a.b'), /compact JWS/);
  assert.throws(() => decodeMandate(`${b64u.encode('{"alg":"none","typ":"mandate+jws","kid":"x"}')}.${p}.`), /bad mandate header/);
});
