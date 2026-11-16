/**
 * Verifying reverse proxy. Put it in front of a broker API (for example Alpaca
 * paper trading): signed orders are verified, allowed ones are forwarded,
 * held ones wait for approval, denied ones never reach the broker.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { randomId } from '../core/encoding.js';
import { MANDATE_HEADERS } from '../core/http.js';
import type { AccountContext, HttpRequestLike, Position } from '../core/types.js';
import { readBody, targetUriOf, denyBody, holdBody } from '../verifier/middleware.js';
import type { Verifier, ContextArgs, VerifyResult } from '../verifier/index.js';

export interface ProxyOptions {
  verifier: Verifier;
  /** Upstream base URL, e.g. https://paper-api.alpaca.markets */
  upstream: string;
  /** Public base URL agents sign against. Default: derived from each request. */
  publicUrl?: string;
  trustProxy?: boolean;
  /** Token for the approval endpoints (/_mandate/holds). Without it they are disabled. */
  adminToken?: string;
  log?: (line: string) => void;
  fetch?: typeof fetch;
}

interface Held {
  id: string;
  created: number;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: Buffer;
  result: VerifyResult;
}

const HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length']);

function forwardHeaders(h: IncomingMessage['headers']): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    const lk = k.toLowerCase();
    if (v === undefined || HOP.has(lk) || MANDATE_HEADERS.includes(lk)) continue;
    out[lk] = Array.isArray(v) ? v.join(', ') : v;
  }
  return out;
}

export function createProxy(opts: ProxyOptions): { server: Server; holds: Map<string, Held> } {
  const upstream = opts.upstream.replace(/\/+$/, '');
  const f = opts.fetch ?? fetch;
  const holds = new Map<string, Held>();
  const log = opts.log ?? (() => {});

  const forward = async (method: string, path: string, headers: Record<string, string>, body: Buffer, res: ServerResponse, extra: Record<string, string> = {}) => {
    const r = await f(upstream + path, { method, headers, body: body.length && method !== 'GET' && method !== 'HEAD' ? new Uint8Array(body) : undefined, redirect: 'manual' });
    const out: Record<string, string> = { ...extra };
    r.headers.forEach((v, k) => { if (!HOP.has(k) && k !== 'content-encoding') out[k] = v; });
    res.writeHead(r.status, out);
    res.end(Buffer.from(await r.arrayBuffer()));
  };

  const isAdmin = (req: IncomingMessage) => {
    if (!opts.adminToken) return false;
    const got = Buffer.from(req.headers.authorization ?? '');
    const want = Buffer.from(`Bearer ${opts.adminToken}`);
    return got.length === want.length && timingSafeEqual(got, want);
  };

  const json = (res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...extra });
    res.end(JSON.stringify(body));
  };

  const handle = async (req: IncomingMessage, res: ServerResponse) => {
    const path = req.url ?? '/';
    const method = (req.method ?? 'GET').toUpperCase();

    // Approval endpoints for held orders.
    if (path.startsWith('/_mandate/')) {
      if (!isAdmin(req)) return json(res, 403, { error: 'admin token required' });
      if (method === 'GET' && path === '/_mandate/holds')
        return json(res, 200, [...holds.values()].map((h) => ({ id: h.id, created: h.created, method: h.method, path: h.path, order: h.result.order, reasons: h.result.reasons, agent: h.result.agent?.kid, sub: h.result.mandate?.sub })));
      const m = /^\/_mandate\/holds\/([A-Za-z0-9_-]+)\/(approve|reject)$/.exec(path);
      if (method === 'POST' && m) {
        const h = holds.get(m[1]!);
        if (!h) return json(res, 404, { error: 'not_found' });
        holds.delete(h.id);
        if (m[2] === 'reject') {
          log(`hold ${h.id} rejected`);
          return json(res, 200, { id: h.id, status: 'rejected' });
        }
        opts.verifier.recordApproved(h.result);
        log(`hold ${h.id} approved, forwarding`);
        return forward(h.method, h.path, h.headers, h.body, res, { 'mandate-decision': `allow; approved="${h.id}"` });
      }
      return json(res, 404, { error: 'not_found' });
    }

    const body = await readBody(req);
    const url = opts.publicUrl ? opts.publicUrl.replace(/\/+$/, '') + path : targetUriOf(req, opts.trustProxy);
    const result = await opts.verifier.verify({ method, url, headers: req.headers, body });
    const sym = result.order ? `${result.order.side} ${result.order.qty ?? ''}${result.order.notional ? '$' + result.order.notional : ''} ${result.order.symbol}`.replace(/\s+/g, ' ') : path;
    log(`${result.decision.toUpperCase().padEnd(5)} ${method} ${sym} [${result.reasons.map((r) => r.code).join(', ') || 'ok'}] agent=${result.agent?.kid.slice(0, 8) ?? '-'}`);

    if (result.decision === 'deny') return json(res, 403, denyBody(result));
    if (result.decision === 'hold') {
      const id = 'hold_' + randomId(9);
      holds.set(id, { id, created: Date.now(), method, path, headers: forwardHeaders(req.headers), body, result });
      return json(res, 202, holdBody(result, id));
    }
    return forward(method, path, forwardHeaders(req.headers), body, res, { 'mandate-decision': `allow; evidence="${result.evidence.hash}"` });
  };

  const server = createServer((req, res) => {
    handle(req, res).catch((e: any) => json(res, e?.status ?? 502, { error: e?.status ? e.message : 'upstream error' }));
  });
  return { server, holds };
}

/**
 * Account context from the Alpaca Trading API, using the credentials on the
 * agent's own request (APCA-API-KEY-ID / APCA-API-SECRET-KEY) or fixed ones.
 */
export function alpacaContext(opts: { tradingUrl: string; dataUrl?: string; keyId?: string; secret?: string; fetch?: typeof fetch }) {
  const f = opts.fetch ?? fetch;
  const base = opts.tradingUrl.replace(/\/+$/, '');
  return async ({ order, request }: ContextArgs): Promise<AccountContext | undefined> => {
    const hdr = (n: string) => {
      const h = (request as HttpRequestLike).headers as Record<string, string | string[] | undefined>;
      const v = h[n] ?? h[n.toLowerCase()];
      return Array.isArray(v) ? v[0] : v;
    };
    const keyId = opts.keyId ?? hdr('apca-api-key-id');
    const secret = opts.secret ?? hdr('apca-api-secret-key');
    const auth: Record<string, string> = {};
    if (keyId && secret) {
      auth['APCA-API-KEY-ID'] = keyId;
      auth['APCA-API-SECRET-KEY'] = secret;
    } else {
      const a = hdr('authorization');
      if (a) auth.authorization = a;
      else return undefined;
    }
    const [acct, pos] = await Promise.all([f(`${base}/v2/account`, { headers: auth }), f(`${base}/v2/positions`, { headers: auth })]);
    if (!acct.ok || !pos.ok) return undefined;
    const a = (await acct.json()) as { equity: string };
    const list = (await pos.json()) as { symbol: string; qty: string; market_value: string; current_price: string; side: string }[];
    const positions: Record<string, Position> = {};
    for (const p of list) {
      const qty = Number(p.qty);
      positions[p.symbol.toUpperCase().replace('/', '')] = { qty, market_value: Math.abs(Number(p.market_value)), price: Number(p.current_price) };
      positions[p.symbol.toUpperCase()] = positions[p.symbol.toUpperCase().replace('/', '')]!;
    }
    const prices: Record<string, number> = {};
    const sym = order.symbol.toUpperCase();
    if (!positions[sym] && !order.notional && !order.limit_price && opts.dataUrl && order.asset_class !== 'crypto' && order.asset_class !== 'option') {
      try {
        const r = await f(`${opts.dataUrl.replace(/\/+$/, '')}/v2/stocks/${encodeURIComponent(sym)}/trades/latest`, { headers: auth });
        if (r.ok) {
          const t = (await r.json()) as { trade?: { p: number } };
          if (t.trade?.p) prices[sym] = t.trade.p;
        }
      } catch { /* no price: verifier will hold with notional_unknown */ }
    }
    return { equity: Number(a.equity), positions, prices };
  };
}
