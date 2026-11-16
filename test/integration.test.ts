import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { setup } from './helpers.js';
import { createProxy } from '../src/proxy/index.js';
import { createAgent } from '../src/agent/index.js';
import { mcpAdapter, alpacaAdapter, classify } from '../src/adapters/index.js';
import { mandateMiddleware, verifyFetchRequest } from '../src/verifier/middleware.js';
import { runDemo } from '../src/cli/demo.js';

async function upstream() {
  const seen: { headers: Record<string, unknown>; body: string }[] = [];
  const s = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ headers: req.headers, body });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"id":"ord_1","status":"accepted"}');
    });
  });
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  return { s, seen, url: `http://127.0.0.1:${(s.address() as AddressInfo).port}` };
}

test('proxy: allow forwards without Mandate headers; deny never reaches the broker; hold waits for approval', async (t) => {
  const up = await upstream();
  const s = setup();
  const { server } = createProxy({ verifier: s.verifier, upstream: up.url, adminToken: 'tok' });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  t.after(() => { server.close(); up.s.close(); });
  const agent = createAgent({ key: s.agent, mandate: s.mandate });

  const ok = await agent.fetch(`${base}/v2/orders`, { json: { symbol: 'MSFT', qty: '1', side: 'buy', type: 'market' }, headers: { 'APCA-API-KEY-ID': 'k' } });
  assert.equal(ok.status, 200);
  assert.match(ok.headers.get('mandate-decision') ?? '', /^allow; evidence=/);
  assert.equal(up.seen.length, 1);
  assert.equal(up.seen[0]!.headers['signature'], undefined);
  assert.equal(up.seen[0]!.headers['mandate'], undefined);
  assert.equal(up.seen[0]!.headers['apca-api-key-id'], 'k');

  const no = await agent.fetch(`${base}/v2/orders`, { json: { symbol: 'GME', qty: '1', side: 'buy', type: 'market' } });
  assert.equal(no.status, 403);
  assert.equal(((await no.json()) as any).reasons[0].code, 'symbol_denied');
  assert.equal(up.seen.length, 1);

  const held = await agent.fetch(`${base}/v2/orders`, { json: { symbol: 'MSFT', qty: '30', side: 'buy', type: 'market' } });
  assert.equal(held.status, 202);
  const { approval_id } = (await held.json()) as any;
  assert.equal((await fetch(`${base}/_mandate/holds`)).status, 403);
  const list = (await (await fetch(`${base}/_mandate/holds`, { headers: { authorization: 'Bearer tok' } })).json()) as any[];
  assert.equal(list[0].id, approval_id);
  const approved = await fetch(`${base}/_mandate/holds/${approval_id}/approve`, { method: 'POST', headers: { authorization: 'Bearer tok' } });
  assert.equal(approved.status, 200);
  assert.equal(up.seen.length, 2);
  assert.match(up.seen[1]!.body, /"qty":"30"/);
});

test('express-style middleware and fetch Request binding', async (t) => {
  const s = setup();
  const mw = mandateMiddleware(s.verifier);
  const app = createServer((req, res) => mw(req as any, res, (err?: unknown) => {
    res.writeHead(err ? 500 : 200);
    res.end(err ? 'err' : 'reached handler');
  }));
  await new Promise<void>((r) => app.listen(0, '127.0.0.1', r));
  t.after(() => app.close());
  const base = `http://127.0.0.1:${(app.address() as AddressInfo).port}`;
  const agent = createAgent({ key: s.agent, mandate: s.mandate });
  const r1 = await agent.fetch(`${base}/v2/orders`, { json: { symbol: 'MSFT', qty: '1', side: 'buy', type: 'market' } });
  assert.equal(await r1.text(), 'reached handler');
  const r2 = await fetch(`${base}/v2/orders`, { method: 'POST', body: '{}' });
  assert.equal(r2.status, 403);

  const s2 = setup();
  const a2 = createAgent({ key: s2.agent, mandate: s2.mandate });
  const h = a2.sign({ method: 'POST', url: 'https://broker.example/v2/orders', body: '{"symbol":"GME","qty":"1","side":"buy","type":"market"}' });
  const req = new Request('https://broker.example/v2/orders', { method: 'POST', headers: { ...h }, body: '{"symbol":"GME","qty":"1","side":"buy","type":"market"}' });
  const v = await verifyFetchRequest(s2.verifier, req);
  assert.equal(v.response?.status, 403);
});

test('agent refuses a mandate issued to another key', () => {
  const s = setup();
  const other = setup();
  assert.throws(() => createAgent({ key: other.agent, mandate: s.mandate }), /different agent/);
});

test('adapters: Alpaca orders, MCP tool calls, asset classes', () => {
  const a = alpacaAdapter({ etfs: ['SPY'] });
  const u = new URL('https://x/v2/orders');
  const r = a.extract({ method: 'POST', url: u, json: { symbol: 'spy', notional: '100', side: 'buy', type: 'market' } });
  assert.ok(r.kind === 'order' && r.order.asset_class === 'etf' && r.order.notional === 100 && r.order.symbol === 'SPY');
  assert.equal(a.extract({ method: 'GET', url: u, json: undefined }).kind, 'none');
  assert.equal(a.extract({ method: 'PATCH', url: new URL('https://x/v2/orders/abc'), json: {} }).kind, 'unreadable');
  assert.equal(classify('AAPL250117C00200000'), 'option');
  assert.equal(classify('ETH/USD'), 'crypto');

  const m = mcpAdapter();
  const mu = new URL('https://x/mcp');
  const call = (name: string, args: object) => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  const o = m.extract({ method: 'POST', url: mu, json: call('place_order', { symbol: 'MSFT', quantity: 3, side: 'buy' }) });
  assert.ok(o.kind === 'order' && o.order.qty === 3 && o.order.type === 'market');
  const b = m.extract({ method: 'POST', url: mu, json: call('buy_stock', { ticker: 'nvda', amount: 50 }) });
  assert.ok(b.kind === 'order' && b.order.side === 'buy' && b.order.symbol === 'NVDA' && b.order.notional === 50);
  assert.equal(m.extract({ method: 'POST', url: mu, json: call('get_positions', {}) }).kind, 'none');
  assert.equal(m.extract({ method: 'POST', url: mu, json: call('cancel_order', { id: 'x' }) }).kind, 'none');
  assert.equal(m.extract({ method: 'POST', url: mu, json: call('place_order', { symbol: 'MSFT' }) }).kind, 'unreadable');
  assert.equal(m.extract({ method: 'POST', url: mu, json: [call('place_order', { symbol: 'A', qty: 1, side: 'buy' }), call('place_order', { symbol: 'B', qty: 1, side: 'buy' })] }).kind, 'unreadable');
});

test('demo: only the two legitimate orders reach the broker', async () => {
  const lines: string[] = [];
  assert.ok(await runDemo((l) => lines.push(l)));
  assert.equal(lines.filter((l) => l.includes('ALLOW')).length, 2);
});
