/** Map a broker's request format to the normalised order (spec section 7.3). */
import type { AssetClass, Order, OrderType, Side } from '../core/types.js';

export type Extracted =
  | { kind: 'order'; order: Order }
  | { kind: 'none' }
  | { kind: 'unreadable'; message: string };

export interface AdapterRequest {
  method: string;
  url: URL;
  json: unknown;
}

export interface OrderAdapter {
  name: string;
  extract(req: AdapterRequest): Extracted;
}

const OCC_OPTION = /^[A-Z]{1,6}\d{6}[CP]\d{8}$/;

export function classify(symbol: string, etfs?: Set<string>): AssetClass {
  const s = symbol.toUpperCase();
  if (s.includes('/')) return 'crypto';
  if (OCC_OPTION.test(s)) return 'option';
  if (etfs?.has(s)) return 'etf';
  return 'us_equity';
}

function num(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

const TYPES: OrderType[] = ['market', 'limit', 'stop', 'stop_limit', 'trailing_stop'];

/** Build an order from loosely named fields (Alpaca style, plus common aliases). */
export function orderFromFields(a: Record<string, unknown>, etfs?: Set<string>): Order | string {
  const symbol = typeof a.symbol === 'string' ? a.symbol.trim().toUpperCase() : typeof a.ticker === 'string' ? a.ticker.trim().toUpperCase() : '';
  if (!symbol) return 'order has no symbol';
  const sideRaw = String(a.side ?? a.action ?? '').toLowerCase();
  const side: Side | undefined = sideRaw === 'buy' || sideRaw === 'sell' ? sideRaw : undefined;
  if (!side) return 'order side must be buy or sell';
  const typeRaw = String(a.type ?? a.order_type ?? 'market').toLowerCase() as OrderType;
  if (!TYPES.includes(typeRaw)) return `unsupported order type ${typeRaw}`;
  const qty = num(a.qty ?? a.quantity ?? a.shares);
  const notional = num(a.notional ?? a.amount);
  if (qty === undefined && notional === undefined) return 'order needs qty or notional';
  if ((qty !== undefined && qty <= 0) || (notional !== undefined && notional <= 0)) return 'qty and notional must be positive';
  const assetRaw = typeof a.asset_class === 'string' ? (a.asset_class as AssetClass) : undefined;
  const order: Order = { symbol, side, type: typeRaw, asset_class: assetRaw ?? classify(symbol, etfs) };
  if (qty !== undefined) order.qty = qty;
  if (notional !== undefined) order.notional = notional;
  const lp = num(a.limit_price), sp = num(a.stop_price);
  if (lp !== undefined) order.limit_price = lp;
  if (sp !== undefined) order.stop_price = sp;
  if (typeof a.time_in_force === 'string') order.time_in_force = a.time_in_force;
  if (typeof a.client_order_id === 'string') order.client_order_id = a.client_order_id;
  return order;
}

/** Alpaca Trading API: POST /v2/orders. Replacing an order (PATCH) is not readable in draft 0.1. */
export function alpacaAdapter(opts: { etfs?: string[] } = {}): OrderAdapter {
  const etfs = opts.etfs ? new Set(opts.etfs.map((s) => s.toUpperCase())) : undefined;
  return {
    name: 'alpaca',
    extract({ method, url, json }) {
      const path = url.pathname.replace(/\/+$/, '');
      if (method === 'POST' && /\/v2\/orders$/.test(path)) {
        if (!json || typeof json !== 'object') return { kind: 'unreadable', message: 'order body is not JSON' };
        const j = json as Record<string, unknown>;
        if (j.order_class === 'mleg' || Array.isArray(j.legs)) return { kind: 'unreadable', message: 'multi-leg orders are not supported in draft 0.1' };
        const o = orderFromFields(j, etfs);
        return typeof o === 'string' ? { kind: 'unreadable', message: o } : { kind: 'order', order: o };
      }
      if (method === 'PATCH' && /\/v2\/orders\/[^/]+$/.test(path)) return { kind: 'unreadable', message: 'order replacement is not supported in draft 0.1; cancel and resubmit' };
      return { kind: 'none' };
    },
  };
}

/** Requests that already carry a normalised order as JSON, on the given path (default any POST to /orders). */
export function genericAdapter(opts: { path?: RegExp; etfs?: string[] } = {}): OrderAdapter {
  const re = opts.path ?? /\/orders$/;
  const etfs = opts.etfs ? new Set(opts.etfs.map((s) => s.toUpperCase())) : undefined;
  return {
    name: 'generic',
    extract({ method, url, json }) {
      if (method !== 'POST' || !re.test(url.pathname.replace(/\/+$/, ''))) return { kind: 'none' };
      if (!json || typeof json !== 'object') return { kind: 'unreadable', message: 'order body is not JSON' };
      const o = orderFromFields(json as Record<string, unknown>, etfs);
      return typeof o === 'string' ? { kind: 'unreadable', message: o } : { kind: 'order', order: o };
    },
  };
}

/**
 * MCP servers: JSON-RPC `tools/call` requests. Tools whose names match `orderTools`
 * (default: anything containing order, trade, buy or sell) are read as orders.
 */
export function mcpAdapter(opts: { orderTools?: RegExp; map?: (tool: string, args: Record<string, unknown>) => Order | string | null; etfs?: string[] } = {}): OrderAdapter {
  const re = opts.orderTools ?? /(order|trade|buy|sell)/i;
  const etfs = opts.etfs ? new Set(opts.etfs.map((s) => s.toUpperCase())) : undefined;
  return {
    name: 'mcp',
    extract({ method, json }) {
      if (method !== 'POST' || !json || typeof json !== 'object') return { kind: 'none' };
      const msgs = Array.isArray(json) ? json : [json];
      const orders: Order[] = [];
      for (const m of msgs as any[]) {
        if (!m || m.method !== 'tools/call' || !m.params) continue;
        const tool = String(m.params.name ?? '');
        const args = (m.params.arguments ?? {}) as Record<string, unknown>;
        let o: Order | string | null;
        if (opts.map) o = opts.map(tool, args);
        else if (re.test(tool) && !/^(get|list|cancel|close)_?/i.test(tool)) {
          const a = { ...args };
          if (a.side === undefined && /buy/i.test(tool)) a.side = 'buy';
          if (a.side === undefined && /sell/i.test(tool)) a.side = 'sell';
          o = orderFromFields(a, etfs);
        } else o = null;
        if (typeof o === 'string') return { kind: 'unreadable', message: `${tool}: ${o}` };
        if (o) orders.push(o);
      }
      if (orders.length > 1) return { kind: 'unreadable', message: 'one order per request in draft 0.1' };
      return orders.length ? { kind: 'order', order: orders[0]! } : { kind: 'none' };
    },
  };
}
