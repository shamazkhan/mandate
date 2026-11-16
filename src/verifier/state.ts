/** Usage counters for daily notional and rate limits, and replay protection. */

export interface StateStore {
  /** Returns true if this nonce was unseen (and records it), false if it is a replay. */
  checkNonce(kid: string, nonce: string, expiresAt: number): boolean;
  usage(mid: string, nowMs: number): { daily_notional: number; orders_last_minute: number };
  record(mid: string, notional: number, nowMs: number): void;
}

const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export class MemoryState implements StateStore {
  private nonces = new Map<string, number>();
  private daily = new Map<string, { day: string; total: number }>();
  private recent = new Map<string, number[]>();
  private sweeps = 0;

  checkNonce(kid: string, nonce: string, expiresAt: number): boolean {
    const now = Date.now() / 1000;
    if (++this.sweeps % 500 === 0) for (const [k, exp] of this.nonces) if (exp < now) this.nonces.delete(k);
    const key = kid + ' ' + nonce;
    const seen = this.nonces.get(key);
    if (seen !== undefined && seen >= now) return false;
    this.nonces.set(key, expiresAt + 60);
    return true;
  }

  usage(mid: string, nowMs: number) {
    const d = this.daily.get(mid);
    const list = (this.recent.get(mid) ?? []).filter((t) => t > nowMs - 60_000);
    this.recent.set(mid, list);
    return { daily_notional: d && d.day === day(nowMs) ? d.total : 0, orders_last_minute: list.length };
  }

  record(mid: string, notional: number, nowMs: number): void {
    const d = this.daily.get(mid);
    const today = day(nowMs);
    this.daily.set(mid, { day: today, total: (d && d.day === today ? d.total : 0) + (notional || 0) });
    const list = this.recent.get(mid) ?? [];
    list.push(nowMs);
    this.recent.set(mid, list);
  }
}
