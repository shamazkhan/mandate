import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import { b64u, sha256, nowSeconds } from './encoding.js';
import type { KeyFile, KeyType, PrivateJwk, PublicJwk } from './types.js';

export function isPublicJwk(j: unknown): j is PublicJwk {
  const o = j as PublicJwk;
  return !!o && o.kty === 'OKP' && o.crv === 'Ed25519' && typeof o.x === 'string' && b64u.decode(o.x).length === 32;
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url). This is the key's `kid`. */
export function thumbprint(jwk: PublicJwk): string {
  if (!isPublicJwk(jwk)) throw new Error('not an Ed25519 public JWK');
  return b64u.encode(sha256(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`));
}

export function publicOf(jwk: PrivateJwk | PublicJwk): PublicJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: jwk.x };
}

export function generateKey(type: KeyType): KeyFile {
  const { privateKey } = generateKeyPairSync('ed25519');
  const jwk = privateKey.export({ format: 'jwk' }) as unknown as PrivateJwk;
  const full: PrivateJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d };
  return { kid: thumbprint(full), type, jwk: full, created_at: nowSeconds() };
}

/** Deterministic key from a 32-byte seed. For test vectors only. */
export function keyFromSeed(type: KeyType, seed: Uint8Array): KeyFile {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed)]);
  const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const jwk = priv.export({ format: 'jwk' }) as unknown as PrivateJwk;
  const full: PrivateJwk = { kty: 'OKP', crv: 'Ed25519', x: jwk.x, d: jwk.d };
  return { kid: thumbprint(full), type, jwk: full, created_at: 0 };
}

const privCache = new WeakMap<object, KeyObject>();

export function privateKeyObject(jwk: PrivateJwk): KeyObject {
  let k = privCache.get(jwk);
  if (!k) {
    k = createPrivateKey({ key: jwk as unknown as import('node:crypto').JsonWebKey, format: 'jwk' });
    privCache.set(jwk, k);
  }
  return k;
}

export function publicKeyObject(jwk: PublicJwk): KeyObject {
  return createPublicKey({ key: publicOf(jwk) as unknown as import('node:crypto').JsonWebKey, format: 'jwk' });
}

export function signBytes(jwk: PrivateJwk, data: Uint8Array | string): Buffer {
  return edSign(null, typeof data === 'string' ? Buffer.from(data, 'utf8') : data, privateKeyObject(jwk));
}

export function verifyBytes(jwk: PublicJwk, data: Uint8Array | string, sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  try {
    return edVerify(null, typeof data === 'string' ? Buffer.from(data, 'utf8') : data, publicKeyObject(jwk), sig);
  } catch {
    return false;
  }
}

export function parseKeyFile(text: string): KeyFile {
  const k = JSON.parse(text) as KeyFile;
  if (!k || !k.jwk || typeof k.jwk.d !== 'string' || !isPublicJwk(k.jwk)) throw new Error('not a Mandate key file');
  if (!['agent', 'issuer', 'verifier'].includes(k.type)) throw new Error('key file has no valid type');
  if (thumbprint(k.jwk) !== k.kid) throw new Error('key file kid does not match its key');
  return k;
}
