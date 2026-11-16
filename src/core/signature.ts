/**
 * RFC 9421 HTTP Message Signatures, profiled for Mandate Protocol draft 0.1.
 */
import { b64u, nowSeconds, randomId, toBytes } from './encoding.js';
import { contentDigest } from './digest.js';
import { getHeader } from './http.js';
import { signBytes, verifyBytes } from './keys.js';
import { parseDictionary, serializeInnerList, byteSequenceMember, type BareItem, type Member } from './structured.js';
import { SIGNATURE_LABEL, SIGNATURE_TAG, type HttpRequestLike, type PrivateJwk, type PublicJwk } from './types.js';

export const MAX_SIGNATURE_WINDOW = 300;

export interface SignOptions {
  method: string;
  url: string;
  body?: Uint8Array | string | null;
  mandate: string;
  key: { kid: string; jwk: PrivateJwk };
  /** Unix seconds; defaults to now. */
  created?: number;
  /** Seconds the signature stays valid; default 60, max 300. */
  ttl?: number;
  nonce?: string;
}

export interface SignedHeaders {
  'Mandate': string;
  'Content-Digest'?: string;
  'Signature-Input': string;
  'Signature': string;
}

function componentValue(name: string, method: string, url: string, headers: (h: string) => string | undefined): string | undefined {
  switch (name) {
    case '@method': return method.toUpperCase();
    case '@target-uri': return url;
    case '@authority': return new URL(url).host.toLowerCase();
    case '@path': return new URL(url).pathname;
    case '@query': return new URL(url).search || '?';
    default:
      if (name.startsWith('@')) return undefined;
      return headers(name)?.trim();
  }
}

export function signatureBase(components: string[], paramsRaw: string, method: string, url: string, headers: (h: string) => string | undefined): string | null {
  const lines: string[] = [];
  for (const c of components) {
    const v = componentValue(c, method, url, headers);
    if (v === undefined) return null;
    lines.push(`"${c}": ${v}`);
  }
  lines.push(`"@signature-params": ${paramsRaw}`);
  return lines.join('\n');
}

/** Sign a request. Returns the headers to add to it. */
export function signRequest(opts: SignOptions): SignedHeaders {
  const hasBody = toBytes(opts.body).length > 0;
  const created = opts.created ?? nowSeconds();
  const ttl = Math.min(opts.ttl ?? 60, MAX_SIGNATURE_WINDOW);
  const components = hasBody ? ['@method', '@target-uri', 'content-digest', 'mandate'] : ['@method', '@target-uri', 'mandate'];
  const params: [string, BareItem][] = [
    ['created', created],
    ['expires', created + ttl],
    ['keyid', opts.key.kid],
    ['alg', 'ed25519'],
    ['nonce', opts.nonce ?? randomId(16)],
    ['tag', SIGNATURE_TAG],
  ];
  const paramsRaw = serializeInnerList(components, params);
  const out: SignedHeaders = { 'Mandate': opts.mandate, 'Signature-Input': '', 'Signature': '' };
  if (hasBody) out['Content-Digest'] = contentDigest(opts.body);
  const lookup = (h: string) => (h === 'content-digest' ? out['Content-Digest'] : h === 'mandate' ? out.Mandate : undefined);
  const base = signatureBase(components, paramsRaw, opts.method, opts.url, lookup)!;
  const sig = signBytes(opts.key.jwk, base);
  out['Signature-Input'] = `${SIGNATURE_LABEL}=${paramsRaw}`;
  out['Signature'] = `${SIGNATURE_LABEL}=:${sig.toString('base64')}:`;
  return out;
}

export interface ParsedSignature {
  label: string;
  components: string[];
  paramsRaw: string;
  created?: number;
  expires?: number;
  keyid?: string;
  alg?: string;
  nonce?: string;
  tag?: string;
  signature: Uint8Array;
}

function str(v: BareItem | undefined): string | undefined {
  return typeof v === 'string' ? v : undefined;
}
function int(v: BareItem | undefined): number | undefined {
  return typeof v === 'number' && Number.isInteger(v) ? v : undefined;
}

/**
 * Find the Mandate signature on a request. Prefers the member labelled `mandate`;
 * otherwise the first member whose tag is `mandate/0.1`.
 */
export function parseSignature(req: HttpRequestLike): ParsedSignature | null {
  const si = getHeader(req.headers, 'signature-input');
  const sg = getHeader(req.headers, 'signature');
  if (!si || !sg) return null;
  let inputs: Map<string, Member>, sigs: Map<string, Member>;
  try {
    inputs = parseDictionary(si);
    sigs = parseDictionary(sg);
  } catch {
    return null;
  }
  let label: string | undefined = inputs.has(SIGNATURE_LABEL) ? SIGNATURE_LABEL : undefined;
  if (!label) {
    for (const [k, m] of inputs) if (m.kind === 'inner' && str(m.params.get('tag')) === SIGNATURE_TAG) { label = k; break; }
  }
  if (!label) return null;
  const input = inputs.get(label)!;
  const signature = byteSequenceMember(sigs.get(label));
  if (input.kind !== 'inner' || !signature) return null;
  const components: string[] = [];
  for (const it of input.items) {
    if (typeof it.value !== 'string' || it.params.size > 0) return null;
    components.push(it.value);
  }
  return {
    label,
    components,
    paramsRaw: input.raw,
    created: int(input.params.get('created')),
    expires: int(input.params.get('expires')),
    keyid: str(input.params.get('keyid')),
    alg: str(input.params.get('alg')),
    nonce: str(input.params.get('nonce')),
    tag: str(input.params.get('tag')),
    signature,
  };
}

/** Verify the cryptographic signature only. Freshness, digest and key status are checked by the verifier. */
export function verifySignature(req: HttpRequestLike, parsed: ParsedSignature, jwk: PublicJwk): boolean {
  const base = signatureBase(parsed.components, parsed.paramsRaw, req.method, req.url, (h) => getHeader(req.headers, h));
  if (base === null) return false;
  return verifyBytes(jwk, base, parsed.signature);
}

export function requiredComponents(hasBody: boolean): string[] {
  return hasBody ? ['@method', '@target-uri', 'content-digest', 'mandate'] : ['@method', '@target-uri', 'mandate'];
}

export { b64u };
