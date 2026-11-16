import { timingSafeEqual } from 'node:crypto';
import { sha256, toBytes } from './encoding.js';
import { parseDictionary, byteSequenceMember } from './structured.js';

/** RFC 9530 Content-Digest value using sha-256. */
export function contentDigest(body: Uint8Array | string | null | undefined): string {
  return `sha-256=:${sha256(toBytes(body)).toString('base64')}:`;
}

/** True if the header carries a sha-256 digest that matches the body. */
export function checkContentDigest(header: string | undefined, body: Uint8Array | string | null | undefined): boolean {
  if (!header) return false;
  let dict;
  try {
    dict = parseDictionary(header);
  } catch {
    return false;
  }
  const got = byteSequenceMember(dict.get('sha-256'));
  if (!got || got.length !== 32) return false;
  return timingSafeEqual(Buffer.from(got), sha256(toBytes(body)));
}
