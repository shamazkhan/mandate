/** Policy evaluation, Mandate Protocol draft 0.1 section 7.2. */
import type { AccountContext, Decision, Order, Policy, Reason, ReasonCode } from './types.js';

export interface Usage {
  /** Notional of allowed orders today (UTC) under this mandate. */
  daily_notional: number;
  /** Orders allowed in the last 60 seconds under this mandate. */
  orders_last_minute: number;
}

export interface PolicyResult {
  decision: Decision;
  reasons: Reason[];
  /** Estimated notional, if it could be determined. */
  notional?: number;
  exit: boolean;
}

const HOLD_CODES: ReasonCode[] = ['approval_required', 'notional_unknown', 'context_unavailable'];

export function combine(reasons: Reason[]): Decision {
  const blocking = reasons.filter((r) => r.code !== 'exit_always_allowed' && r.code !== 'not_an_order');
  if (blocking.some((r) => !HOLD_CODES.includes(r.code))) return 'deny';
  if (blocking.length) return 'hold';
  return 'allow';
}

const up = (s: string) => s.trim().toUpperCase();

function referencePrice(order: Order, ctx: AccountContext | undefined): number | undefined {
  if (order.limit_price && order.limit_price > 0) return order.limit_price;
  const sym = up(order.symbol);
  return ctx?.prices?.[sym] ?? ctx?.positions?.[sym]?.price;
}

export function estimateNotional(order: Order, ctx?: AccountContext): number | undefined {
  if (typeof order.notional === 'number' && order.notional > 0) return order.notional;
  if (typeof order.qty === 'number' && order.qty > 0) {
    const p = referencePrice(order, ctx);
    if (p !== undefined && (order.type !== 'stop' || !order.stop_price)) return order.qty * p;
    if (order.stop_price) return order.qty * order.stop_price;
    if (p !== undefined) return order.qty * p;
  }
  return undefined;
}

/** An exit only reduces an existing position. */
export function isExit(order: Order, ctx?: AccountContext): boolean {
  const pos = ctx?.positions?.[up(order.symbol)];
  if (!pos || pos.qty === 0) return false;
  if (order.side === 'sell' && pos.qty > 0) {
    if (typeof order.qty === 'number') return order.qty > 0 && order.qty <= pos.qty;
    if (typeof order.notional === 'number' && pos.market_value !== undefined) return order.notional <= Math.abs(pos.market_value);
    return false;
  }
  if (order.side === 'buy' && pos.qty < 0) {
    if (typeof order.qty === 'number') return order.qty > 0 && order.qty <= -pos.qty;
    return false;
  }
  return false;
}

function fmt(n: number): string {
  return n.toLocaleString('en-US', { maximumFractionDigits: 2 });
}

export function evaluatePolicy(policy: Policy, order: Order, ctx: AccountContext | undefined, usage: Usage): PolicyResult {
  const reasons: Reason[] = [];
  const add = (code: ReasonCode, message: string) => reasons.push({ code, message });
  const cur = policy.currency ?? 'USD';
  const sym = up(order.symbol);
  const exit = isExit(order, ctx);

  if (exit && (policy.exits ?? 'always_allow') === 'always_allow') {
    return { decision: 'allow', reasons: [{ code: 'exit_always_allowed', message: `Exit of an existing ${sym} position is always allowed.` }], notional: estimateNotional(order, ctx), exit };
  }

  if (policy.instruments && !policy.instruments.includes(order.asset_class)) add('instrument_not_allowed', `Asset class ${order.asset_class} is not in the mandate.`);
  const deny = policy.symbols?.deny?.map(up);
  const allow = policy.symbols?.allow?.map(up);
  if (deny?.includes(sym)) add('symbol_denied', `${sym} is on the mandate's deny list.`);
  else if (allow && !allow.includes(sym)) add('symbol_not_allowed', `${sym} is not on the mandate's allow list.`);
  if (policy.sides && !policy.sides.includes(order.side)) add('side_not_allowed', `Side ${order.side} is not allowed.`);
  if (policy.order_types && !policy.order_types.includes(order.type)) add('order_type_not_allowed', `Order type ${order.type} is not allowed.`);

  if (order.side === 'sell' && policy.allow_short !== true) {
    const pos = ctx?.positions?.[sym];
    if (!ctx?.positions) add('context_unavailable', 'Positions are needed to rule out short selling.');
    else if (!pos || pos.qty <= 0 || (typeof order.qty === 'number' && order.qty > pos.qty)) add('short_not_allowed', `Selling ${sym} would open or increase a short position.`);
  }

  const notional = estimateNotional(order, ctx);
  const needsNotional = policy.max_order_notional !== undefined || policy.max_daily_notional !== undefined ||
    policy.max_position_pct !== undefined || policy.max_leverage !== undefined || policy.require_approval?.above_notional !== undefined;

  if (notional === undefined) {
    if (needsNotional) add('notional_unknown', 'Order value could not be determined (no notional, limit price or reference price).');
  } else {
    if (policy.max_order_notional !== undefined && notional > policy.max_order_notional)
      add('order_notional_exceeded', `Order value ${cur} ${fmt(notional)} is above the ${cur} ${fmt(policy.max_order_notional)} limit.`);
    if (policy.max_daily_notional !== undefined && usage.daily_notional + notional > policy.max_daily_notional)
      add('daily_notional_exceeded', `Today's total would be ${cur} ${fmt(usage.daily_notional + notional)}, above the ${cur} ${fmt(policy.max_daily_notional)} daily limit.`);

    if (policy.max_position_pct !== undefined || policy.max_leverage !== undefined) {
      const equity = ctx?.equity;
      if (equity === undefined || !ctx?.positions) add('context_unavailable', 'Account equity and positions are needed for position and leverage limits.');
      else if (equity <= 0) add('leverage_exceeded', 'Account equity is zero or negative.');
      else {
        const pos = ctx.positions[sym];
        const posValue = Math.abs(pos?.market_value ?? (pos && pos.price !== undefined ? pos.qty * pos.price : 0));
        const signed = order.side === 'buy' ? 1 : -1;
        const longish = (pos?.qty ?? 0) >= 0;
        const after = longish ? posValue + signed * notional : posValue - signed * notional;
        if (policy.max_position_pct !== undefined) {
          const pct = (Math.abs(after) / equity) * 100;
          if (Math.abs(after) > posValue && pct > policy.max_position_pct)
            add('position_limit_exceeded', `${sym} would be ${fmt(pct)}% of equity, above the ${fmt(policy.max_position_pct)}% limit.`);
        }
        if (policy.max_leverage !== undefined) {
          let gross = 0;
          for (const p of Object.values(ctx.positions)) gross += Math.abs(p.market_value ?? (p.price !== undefined ? p.qty * p.price : 0));
          const grossAfter = gross - posValue + Math.abs(after);
          const lev = grossAfter / equity;
          if (grossAfter > gross && lev > policy.max_leverage)
            add('leverage_exceeded', `Gross exposure would be ${fmt(lev)}x equity, above the ${fmt(policy.max_leverage)}x limit.`);
        }
      }
    }
    if (policy.require_approval?.above_notional !== undefined && notional > policy.require_approval.above_notional)
      add('approval_required', `Orders above ${cur} ${fmt(policy.require_approval.above_notional)} need the account holder's approval.`);
  }

  if (policy.max_orders_per_minute !== undefined && usage.orders_last_minute >= policy.max_orders_per_minute)
    add('rate_limit_exceeded', `More than ${policy.max_orders_per_minute} orders in the last minute.`);

  // de-duplicate context_unavailable
  const seen = new Set<string>();
  const uniq = reasons.filter((r) => (r.code === 'context_unavailable' ? (seen.has(r.code) ? false : (seen.add(r.code), true)) : true));
  return { decision: combine(uniq), reasons: uniq, notional, exit };
}
