/** Hash-chained evidence log, Mandate Protocol draft 0.1 section 9. */
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { b64u, canonicalJson, sha256 } from '../core/encoding.js';
import { signBytes, verifyBytes } from '../core/keys.js';
import { PROTOCOL_VERSION, type Assurance, type Decision, type KeyFile, type Order, type PublicJwk, type ReasonCode } from '../core/types.js';

export interface EvidenceInput {
  decision: Decision;
  reasons: ReasonCode[];
  agent?: string;
  assurance?: Assurance;
  operator?: string;
  mandate?: string;
  sub?: string;
  issuer?: string;
  order?: Order | null;
  request: { method: string; target: string; content_digest?: string };
  verifier: string;
}

export interface EvidenceEntry extends EvidenceInput {
  v: string;
  seq: number;
  ts: number;
  prev: string;
  hash: string;
  sig?: string;
}

export interface EvidenceSink {
  append(e: EvidenceInput): EvidenceEntry;
}

export function entryHash(e: Omit<EvidenceEntry, 'hash' | 'sig'>): string {
  return b64u.encode(sha256(canonicalJson(e)));
}

/**
 * Append-only log. Keeps entries in memory and, if `file` is given, appends
 * JSON Lines to it (resuming the chain from the file's last entry).
 */
export class EvidenceLog implements EvidenceSink {
  readonly entries: EvidenceEntry[] = [];
  private seq = 0;
  private prev = '0';

  constructor(private opts: { file?: string; signer?: KeyFile; keepInMemory?: number } = {}) {
    if (opts.file && existsSync(opts.file)) {
      const lines = readFileSync(opts.file, 'utf8').trim().split('\n').filter(Boolean);
      const last = lines.length ? (JSON.parse(lines[lines.length - 1]!) as EvidenceEntry) : null;
      if (last) {
        this.seq = last.seq;
        this.prev = last.hash;
      }
    }
  }

  append(input: EvidenceInput): EvidenceEntry {
    const body: Omit<EvidenceEntry, 'hash' | 'sig'> = { v: PROTOCOL_VERSION, seq: ++this.seq, ts: Date.now(), prev: this.prev, ...stripUndefined(input) };
    const hash = entryHash(body);
    const entry: EvidenceEntry = { ...body, hash };
    if (this.opts.signer) entry.sig = b64u.encode(signBytes(this.opts.signer.jwk, hash));
    this.prev = hash;
    if (this.opts.file) appendFileSync(this.opts.file, JSON.stringify(entry) + '\n');
    this.entries.push(entry);
    const keep = this.opts.keepInMemory ?? 10_000;
    if (this.entries.length > keep) this.entries.splice(0, this.entries.length - keep);
    return entry;
  }
}

function stripUndefined<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

export interface ChainCheck {
  ok: boolean;
  count: number;
  error?: string;
  at?: number;
}

/** Recompute the chain. Optionally check every entry's signature against a verifier key. */
export function verifyChain(entries: EvidenceEntry[], signer?: PublicJwk): ChainCheck {
  let prev = entries[0]?.seq === 1 ? '0' : entries[0]?.prev ?? '0';
  let seq = (entries[0]?.seq ?? 1) - 1;
  for (const e of entries) {
    const { hash, sig, ...rest } = e;
    if (e.seq !== seq + 1) return { ok: false, count: entries.length, error: `sequence gap before ${e.seq}`, at: e.seq };
    if (e.prev !== prev) return { ok: false, count: entries.length, error: `broken link at ${e.seq}`, at: e.seq };
    if (entryHash(rest) !== hash) return { ok: false, count: entries.length, error: `entry ${e.seq} was modified`, at: e.seq };
    if (signer && (!sig || !verifyBytes(signer, hash, b64u.decode(sig)))) return { ok: false, count: entries.length, error: `bad signature on ${e.seq}`, at: e.seq };
    prev = hash;
    seq = e.seq;
  }
  return { ok: true, count: entries.length };
}

export function readLog(file: string): EvidenceEntry[] {
  return readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as EvidenceEntry);
}
