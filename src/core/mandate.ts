/** Mandate tokens: compact JWS (RFC 7515), EdDSA, typ mandate+jws. */
import { b64u, nowSeconds, randomId } from './encoding.js';
import { signBytes, verifyBytes } from './keys.js';
import { MANDATE_TYP, PROTOCOL_VERSION, type MandatePayload, type Policy, type PrivateJwk, type PublicJwk } from './types.js';

export const MAX_MANDATE_BYTES = 8192;

export interface IssueOptions {
  issuer: { kid: string; jwk: PrivateJwk };
  agent: string;
  sub: string;
  policy: Policy;
  aud?: string[];
  /** Lifetime in seconds. Default 30 days. */
  ttl?: number;
  iat?: number;
  nbf?: number;
  mid?: string;
}

export function issueMandate(o: IssueOptions): string {
  const iat = o.iat ?? nowSeconds();
  const payload: MandatePayload = {
    v: PROTOCOL_VERSION,
    mid: o.mid ?? 'mdt_' + randomId(16),
    iss: o.issuer.kid,
    sub: o.sub,
    agent: o.agent,
    ...(o.aud ? { aud: o.aud } : {}),
    iat,
    ...(o.nbf !== undefined ? { nbf: o.nbf } : {}),
    exp: iat + (o.ttl ?? 30 * 86400),
    policy: o.policy,
  };
  const header = { alg: 'EdDSA', typ: MANDATE_TYP, kid: o.issuer.kid };
  const signingInput = b64u.encode(JSON.stringify(header)) + '.' + b64u.encode(JSON.stringify(payload));
  return signingInput + '.' + b64u.encode(signBytes(o.issuer.jwk, signingInput));
}

export interface DecodedMandate {
  header: { alg: string; typ: string; kid: string };
  payload: MandatePayload;
  signingInput: string;
  signature: Buffer;
}

/** Decode without verifying. Throws on malformed tokens. */
export function decodeMandate(token: string): DecodedMandate {
  if (token.length > MAX_MANDATE_BYTES) throw new Error('mandate too large');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('mandate is not a compact JWS');
  const header = JSON.parse(b64u.decode(parts[0]!).toString('utf8'));
  const payload = JSON.parse(b64u.decode(parts[1]!).toString('utf8'));
  if (!header || header.alg !== 'EdDSA' || header.typ !== MANDATE_TYP || typeof header.kid !== 'string') throw new Error('bad mandate header');
  validatePayload(payload);
  if (payload.iss !== header.kid) throw new Error('mandate iss does not match header kid');
  return { header, payload, signingInput: parts[0] + '.' + parts[1], signature: b64u.decode(parts[2]!) };
}

export function verifyMandateSignature(d: DecodedMandate, issuerJwk: PublicJwk): boolean {
  return verifyBytes(issuerJwk, d.signingInput, d.signature);
}

function validatePayload(p: any): asserts p is MandatePayload {
  const need = (c: boolean, m: string) => { if (!c) throw new Error('bad mandate payload: ' + m); };
  need(p && typeof p === 'object', 'not an object');
  need(p.v === PROTOCOL_VERSION, 'unsupported version');
  need(typeof p.mid === 'string' && p.mid.length >= 16, 'mid');
  need(typeof p.iss === 'string', 'iss');
  need(typeof p.sub === 'string' && p.sub.length > 0, 'sub');
  need(typeof p.agent === 'string', 'agent');
  need(Number.isInteger(p.iat) && Number.isInteger(p.exp) && p.exp > p.iat, 'iat/exp');
  need(p.nbf === undefined || Number.isInteger(p.nbf), 'nbf');
  need(p.aud === undefined || (Array.isArray(p.aud) && p.aud.every((a: unknown) => typeof a === 'string')), 'aud');
  need(p.policy && typeof p.policy === 'object' && !Array.isArray(p.policy), 'policy');
}
