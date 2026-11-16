import type { HttpRequestLike } from './types.js';

/** Read a header from a plain object or a WHATWG Headers instance, case-insensitively. */
export function getHeader(headers: HttpRequestLike['headers'], name: string): string | undefined {
  const lname = name.toLowerCase();
  if (typeof (headers as Headers).get === 'function') {
    const v = (headers as Headers).get(lname);
    return v === null ? undefined : v;
  }
  const obj = headers as Record<string, string | string[] | undefined>;
  for (const k of Object.keys(obj)) {
    if (k.toLowerCase() === lname) {
      const v = obj[k];
      if (v === undefined) return undefined;
      return Array.isArray(v) ? v.map((x) => x.trim()).join(', ') : v;
    }
  }
  return undefined;
}

export const MANDATE_HEADERS = ['mandate', 'signature', 'signature-input', 'content-digest'];
