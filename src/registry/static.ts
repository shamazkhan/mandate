import { thumbprint, publicOf } from '../core/keys.js';
import { nowSeconds } from '../core/encoding.js';
import type { Assurance, KeyFile, KeyRecord, KeyType, Operator, PublicJwk } from '../core/types.js';
import type { Resolver } from './types.js';

/**
 * In-memory registry. Use it offline, in tests, or to pin a fixed set of trusted
 * issuers in front of a remote registry (see `chainResolvers`).
 */
export class StaticRegistry implements Resolver {
  private keys = new Map<string, KeyRecord>();
  private revokedMandates = new Map<string, number>();

  constructor(records: KeyRecord[] = []) {
    for (const r of records) this.put(r);
  }

  put(r: KeyRecord): KeyRecord {
    if (thumbprint(r.jwk) !== r.kid) throw new Error(`kid ${r.kid} does not match its key`);
    this.keys.set(r.kid, { ...r, jwk: publicOf(r.jwk) });
    return r;
  }

  add(key: KeyFile | { kid: string; jwk: PublicJwk; type: KeyType }, extra: { name?: string; operator?: Operator; assurance?: Assurance } = {}): KeyRecord {
    return this.put({
      kid: key.kid,
      type: key.type,
      jwk: publicOf(key.jwk),
      status: 'active',
      assurance: extra.assurance ?? 'basic',
      created_at: nowSeconds(),
      ...(extra.name ? { name: extra.name } : {}),
      ...(extra.operator ? { operator: extra.operator } : {}),
    });
  }

  revokeKey(kid: string): void {
    const r = this.keys.get(kid);
    if (r) this.keys.set(kid, { ...r, status: 'revoked', revoked_at: nowSeconds() });
  }

  setAssurance(kid: string, assurance: Assurance): void {
    const r = this.keys.get(kid);
    if (r) this.keys.set(kid, { ...r, assurance });
  }

  revokeMandate(mid: string): void {
    this.revokedMandates.set(mid, nowSeconds());
  }

  async getKey(kid: string): Promise<KeyRecord | null> {
    return this.keys.get(kid) ?? null;
  }

  async isMandateRevoked(mid: string): Promise<boolean> {
    return this.revokedMandates.has(mid);
  }

  list(): KeyRecord[] {
    return [...this.keys.values()];
  }
}

/** Ask each resolver in turn; the first that knows a key wins. Revocation in any resolver counts. */
export function chainResolvers(...rs: Resolver[]): Resolver {
  return {
    async getKey(kid) {
      for (const r of rs) {
        const k = await r.getKey(kid);
        if (k) return k;
      }
      return null;
    },
    async isMandateRevoked(mid) {
      for (const r of rs) if (await r.isMandateRevoked(mid)) return true;
      return false;
    },
  };
}
