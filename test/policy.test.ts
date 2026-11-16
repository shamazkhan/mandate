import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicy, isExit, estimateNotional } from '../src/core/policy.js';
import type { Order } from '../src/core/types.js';
import { ACCOUNT, POLICY } from './helpers.js';

const none = { daily_notional: 0, orders_last_minute: 0 };
const o = (x: Partial<Order>): Order => ({ symbol: 'MSFT', side: 'buy', type: 'market', asset_class: 'us_equity', qty: 10, ...x });
const run = (x: Partial<Order>, usage = none, policy = POLICY, ctx = ACCOUNT) => evaluatePolicy(policy, o(x), ctx, usage);
const codes = (r: { reasons: { code: string }[] }) => r.reasons.map((x) => x.code).sort();

test('small order within every limit is allowed', () => {
  const r = run({ qty: 10 });
  assert.equal(r.decision, 'allow');
  assert.equal(r.notional, 4000);
});

test('notional: explicit, limit price, reference price, unknown', () => {
  assert.equal(estimateNotional(o({ qty: undefined, notional: 500 })), 500);
  assert.equal(estimateNotional(o({ type: 'limit', limit_price: 10, qty: 3 })), 30);
  assert.equal(estimateNotional(o({ qty: 2 }), ACCOUNT), 800);
  assert.equal(estimateNotional(o({ symbol: 'ZZZZ', qty: 2 }), ACCOUNT), undefined);
});

test('every failing rule is reported, deny beats hold', () => {
  const r = run({ symbol: 'TSLA', qty: 100 });
  assert.equal(r.decision, 'deny');
  assert.deepEqual(codes(r), ['approval_required', 'daily_notional_exceeded', 'order_notional_exceeded', 'position_limit_exceeded']);
});

test('approval threshold holds', () => {
  const r = run({ qty: 30 });
  assert.equal(r.decision, 'hold');
  assert.deepEqual(codes(r), ['approval_required']);
});

test('instrument, symbol, side and order type rules', () => {
  assert.deepEqual(codes(run({ symbol: 'GME' })), ['symbol_denied']);
  assert.deepEqual(codes(run({ asset_class: 'crypto', symbol: 'MSFT' })), ['instrument_not_allowed']);
  assert.deepEqual(codes(run({ type: 'stop', stop_price: 400 })), ['order_type_not_allowed']);
  assert.deepEqual(codes(run({}, none, { ...POLICY, symbols: { allow: ['AAPL'] } })), ['symbol_not_allowed']);
  assert.deepEqual(codes(run({}, none, { sides: ['sell'] })), ['side_not_allowed']);
});

test('daily notional and rate limit use current usage', () => {
  assert.deepEqual(codes(run({ qty: 10 }, { daily_notional: 27_000, orders_last_minute: 0 })), ['daily_notional_exceeded']);
  assert.deepEqual(codes(run({ qty: 1 }, { daily_notional: 0, orders_last_minute: 3 })), ['rate_limit_exceeded']);
});

test('short selling is denied unless allowed', () => {
  assert.deepEqual(codes(run({ side: 'sell', symbol: 'MSFT', qty: 1 }, none, {})), ['short_not_allowed']);
  assert.deepEqual(codes(run({ side: 'sell', symbol: 'AAPL', qty: 60 }, none, {})), ['short_not_allowed']);
  assert.equal(run({ side: 'sell', symbol: 'MSFT', qty: 1 }, none, { allow_short: true }).decision, 'allow');
});

test('exits are always allowed by default, even when every other rule would fail', () => {
  const p = { ...POLICY, symbols: { deny: ['AAPL'] }, instruments: ['etf' as const], max_order_notional: 1 };
  assert.ok(isExit(o({ symbol: 'AAPL', side: 'sell', qty: 50 }), ACCOUNT));
  assert.ok(!isExit(o({ symbol: 'AAPL', side: 'sell', qty: 51 }), ACCOUNT));
  const r = run({ symbol: 'AAPL', side: 'sell', qty: 50 }, { daily_notional: 1e9, orders_last_minute: 99 }, p);
  assert.equal(r.decision, 'allow');
  assert.deepEqual(codes(r), ['exit_always_allowed']);
  assert.equal(run({ symbol: 'AAPL', side: 'sell', qty: 50 }, none, { ...p, exits: 'evaluate' }).decision, 'deny');
});

test('short cover is an exit', () => {
  const ctx = { equity: 1000, positions: { XYZ: { qty: -10, price: 5 } } };
  assert.ok(isExit(o({ symbol: 'XYZ', side: 'buy', qty: 10 }), ctx));
});

test('missing context holds instead of guessing', () => {
  assert.deepEqual(codes(run({ qty: 1 }, none, { max_position_pct: 5 }, { prices: { MSFT: 400 } })), ['context_unavailable']);
  assert.deepEqual(codes(run({ symbol: 'NEW', qty: 1 }, none, { max_order_notional: 5 }, {})), ['notional_unknown']);
  assert.equal(run({ symbol: 'NEW', qty: 1 }, none, {}, {}).decision, 'allow');
});

test('leverage counts gross exposure after the order', () => {
  const ctx = { equity: 10_000, positions: { AAPL: { qty: 40, market_value: 9_200, price: 230 } }, prices: { MSFT: 400 } };
  assert.deepEqual(codes(run({ qty: 3 }, none, { max_leverage: 1 }, ctx)), ['leverage_exceeded']);
  assert.equal(run({ qty: 2 }, none, { max_leverage: 1 }, ctx).decision, 'allow');
});

test('position percentage applies to the position after the order', () => {
  assert.deepEqual(codes(run({ symbol: 'AAPL', qty: 40 }, none, { max_position_pct: 20 })), ['position_limit_exceeded']);
  assert.equal(run({ symbol: 'AAPL', qty: 30 }, none, { max_position_pct: 20 }).decision, 'allow');
});
