import { thumbprint } from '../core/keys.js';
import { canonicalJson, nowSeconds, b64u } from '../core/encoding.js';
import { signBytes } from '../core/keys.js';
import type { Assurance, KeyFile, KeyRecord, Operator } from '../core/types.js';
import type { Resolver } from './types.js';

export interface RegistryClientOptions {
  /** Base URL, e.g. https://registry.example. */
  url: string;
  /** Cache lifetime for key records, seconds. Default 60. */
  ttl?: number;
  /** Cache lifetime for unknown keys, seconds. Default 10. */
  negativeTtl?: number;
  /** Poll /v0/revocations this often, seconds. Default 5. 0 disables polling. */
  pollInterval?: number;
  fetch?: typeof fetch;
  /** Admin bearer token, for registry operators. */
  adminToken?: string;
}

export function proofFor(key: KeyFile, msg: Record<string, unknown>) {
  const ts = nowSeconds();
  return { ts, sig: b64u.encode(signBytes(key.jwk, canonicalJson({ ...msg, ts }))) };
}

/** HTTP client for a Mandate registry, with caching and revocation polling. */
export class RegistryClient implements Resolver {
  private cache = new Map<string, { rec: KeyRecord | null; until: number }>();
  private revoked = new Set<string>();
  private revokedKeys = new Set<string>();
  private lastPoll = 0;
  private since = 0;
  private readonly base: string;
  private readonly f: typeof fetch;

  constructor(private opts: RegistryClientOptions) {
    this.base = opts.url.replace(/\/+$/, '');
    this.f = opts.fetch ?? fetch;
  }

  private async poll(): Promise<void> {
    const every = this.opts.pollInterval ?? 5;
    if (every === 0 || Date.now() - this.lastPoll < every * 1000) return;
    this.lastPoll = Date.now();
    try {
      const r = await this.f(`${this.base}/v0/revocations?since=${this.since}`);
      if (!r.ok) return;
      const j = (await r.json()) as { revocations: { kind: 'key' | 'mandate'; id: string; revoked_at: number }[]; now: number };
      for (const x of j.revocations) {
        if (x.kind === 'mandate') this.revoked.add(x.id);
        else {
          this.revokedKeys.add(x.id);
          this.cache.delete(x.id);
        }
      }
      this.since = j.now;
    } catch {
      /* registry unreachable: keep cached state */
    }
  }

  async getKey(kid: string): Promise<KeyRecord | null> {
    await this.poll();
    const hit = this.cache.get(kid);
    if (hit && hit.until > Date.now()) return hit.rec;
    const r = await this.f(`${this.base}/v0/keys/${encodeURIComponent(kid)}`);
    let rec: KeyRecord | null = null;
    if (r.ok) {
      rec = (await r.json()) as KeyRecord;
      // Key ids are self-certifying: never trust a record whose key does not match.
      if (rec.kid !== kid || thumbprint(rec.jwk) !== kid) rec = null;
    } else if (r.status !== 404) {
      if (hit) return hit.rec;
      throw new Error(`registry error ${r.status}`);
    }
    if (rec && this.revokedKeys.has(kid)) rec = { ...rec, status: 'revoked' };
    const ttl = rec ? (this.opts.ttl ?? 60) : (this.opts.negativeTtl ?? 10);
    this.cache.set(kid, { rec, until: Date.now() + ttl * 1000 });
    return rec;
  }

  async isMandateRevoked(mid: string): Promise<boolean> {
    await this.poll();
    if (this.revoked.has(mid)) return true;
    const r = await this.f(`${this.base}/v0/mandates/${encodeURIComponent(mid)}`);
    if (!r.ok) return false;
    const j = (await r.json()) as { status: string };
    if (j.status === 'revoked') this.revoked.add(mid);
    return j.status === 'revoked';
  }

  private async post(path: string, body: unknown): Promise<any> {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (this.opts.adminToken) headers.authorization = `Bearer ${this.opts.adminToken}`;
    const r = await this.f(`${this.base}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(`registry ${r.status}: ${(j as any).error ?? r.statusText}`);
    return j;
  }

  register(key: KeyFile, info: { name?: string; operator?: Operator } = {}): Promise<KeyRecord> {
    return this.post('/v0/keys', {
      type: key.type,
      jwk: { kty: 'OKP', crv: 'Ed25519', x: key.jwk.x },
      ...info,
      proof: proofFor(key, { op: 'register', kid: key.kid }),
    });
  }

  revokeKey(key: KeyFile | string): Promise<KeyRecord> {
    if (typeof key === 'string') return this.post(`/v0/keys/${encodeURIComponent(key)}/revoke`, {});
    return this.post(`/v0/keys/${encodeURIComponent(key.kid)}/revoke`, { proof: proofFor(key, { op: 'revoke', kid: key.kid }) });
  }

  revokeMandate(mid: string, issuer?: KeyFile): Promise<unknown> {
    const body = issuer ? { kid: issuer.kid, proof: proofFor(issuer, { op: 'revoke_mandate', mid, kid: issuer.kid }) } : {};
    return this.post(`/v0/mandates/${encodeURIComponent(mid)}/revoke`, body);
  }

  setAssurance(kid: string, assurance: Assurance, preflight?: KeyRecord['preflight']): Promise<KeyRecord> {
    return this.post(`/v0/keys/${encodeURIComponent(kid)}/assurance`, { assurance, ...(preflight ? { preflight } : {}) });
  }
}
