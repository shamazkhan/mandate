import type { KeyRecord } from '../core/types.js';

/** What a verifier needs from a registry. */
export interface Resolver {
  getKey(kid: string): Promise<KeyRecord | null>;
  isMandateRevoked(mid: string): Promise<boolean>;
}
