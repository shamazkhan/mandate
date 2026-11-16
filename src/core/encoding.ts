import { createHash, randomBytes } from 'node:crypto';

export const b64u = {
  encode(data: Uint8Array | string): string {
    return Buffer.from(typeof data === 'string' ? Buffer.from(data, 'utf8') : data).toString('base64url');
  },
  decode(s: string): Buffer {
    if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('invalid base64url');
    return Buffer.from(s, 'base64url');
  },
};

export function sha256(data: Uint8Array | string): Buffer {
  return createHash('sha256').update(data).digest();
}

export function randomId(bytes = 16): string {
  return randomBytes(bytes).toString('base64url');
}

export function toBytes(body: Uint8Array | string | null | undefined): Buffer {
  if (body == null) return Buffer.alloc(0);
  return typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
}

/**
 * Canonical JSON: object keys sorted by UTF-16 code units, no whitespace.
 * Equivalent to RFC 8785 (JCS) for the values this protocol uses.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalJson(v === undefined ? null : v)).join(',') + ']';
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
  }
  throw new Error(`canonicalJson: unsupported type ${typeof value}`);
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
