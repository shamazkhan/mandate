/** `mandate demo`: the whole protocol on localhost, no accounts needed. */
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKey } from '../core/keys.js';
import { issueMandate } from '../core/mandate.js';
import { signRequest } from '../core/signature.js';
import { StaticRegistry } from '../registry/static.js';
import { createVerifier } from '../verifier/index.js';
import { alpacaAdapter } from '../adapters/index.js';
import { createProxy } from '../proxy/index.js';
import { EvidenceLog, verifyChain } from '../evidence/index.js';
import type { AccountContext } from '../core/types.js';

const listen = (s: Server) => new Promise<number>((r) => s.listen(0, '127.0.0.1', () => r((s.address() as AddressInfo).port)));

export async function runDemo(out: (s: string) => void = console.log): Promise<boolean> {
  const tty = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (n: number) => (s: string) => (tty ? `\x1b[${n}m${s}\x1b[0m` : s);
  const g = c(32), r = c(31), y = c(33), d = c(2);

  // A pretend broker with Alpaca-shaped endpoints.
  const account: AccountContext = { equity: 100_000, positions: { AAPL: { qty: 50, market_value: 11_500, price: 230 } }, prices: { MSFT: 420, NVDA: 180, TSLA: 400, GME: 25, 'BTC/USD': 90_000 } };
  let filled = 0;
  const broker = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      filled++;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: `ord_${filled}`, status: 'accepted', ...JSON.parse(body || '{}') }));
    });
  });
  const brokerPort = await listen(broker);

  // Keys: an issuer (the platform where the account holder grants access) and an agent.
  const issuer = generateKey('issuer');
  const agent = generateKey('agent');
  const rogue = generateKey('agent');
  const registry = new StaticRegistry();
  registry.add(issuer, { name: 'Demo Brokerage', operator: { name: 'Demo Brokerage' } });
  registry.add(agent, { name: 'momentum-bot', operator: { name: 'Acme Quant' } });
  registry.add(rogue, { name: 'copycat-bot', operator: { name: 'Unknown' } });

  const policy = {
    instruments: ['us_equity', 'etf'] as ('us_equity' | 'etf')[],
    symbols: { deny: ['GME'] },
    order_types: ['market', 'limit'] as ('market' | 'limit')[],
    max_order_notional: 25_000,
    max_position_pct: 20,
    require_approval: { above_notional: 10_000 },
    exits: 'always_allow' as const,
  };
  const mandate = issueMandate({ issuer, agent: agent.kid, sub: 'acct_demo_001', policy, ttl: 3600 });

  const evidence = new EvidenceLog();
  const verifier = createVerifier({ registry, id: 'demo-broker', adapter: alpacaAdapter(), evidence, context: () => account });
  const { server: proxy } = createProxy({ verifier, upstream: `http://127.0.0.1:${brokerPort}` });
  const port = await listen(proxy);
  const url = `http://127.0.0.1:${port}/v2/orders`;

  const send = async (label: string, order: object, opts: { key?: typeof agent; tamper?: boolean; replay?: Record<string, string> } = {}) => {
    const body = JSON.stringify(order);
    const headers: Record<string, string> = opts.replay ?? ({ ...signRequest({ method: 'POST', url, body, mandate, key: opts.key ?? agent }) } as Record<string, string>);
    const sentBody = opts.tamper ? body.replace(/"qty":"?(\d+)"?/, '"qty":"5000"') : body;
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: sentBody });
    const j = (await res.json()) as any;
    const decision = res.status === 200 ? g('ALLOW') : res.status === 202 ? y('HOLD ') : r('DENY ');
    const why = j.reasons ? j.reasons.map((x: any) => x.code).join(', ') : `filled as ${j.id}`;
    out(`  ${decision}  ${label.padEnd(44)} ${d(why)}`);
    return { res, headers };
  };

  out('');
  out('  Mandate Protocol demo · account equity $100,000 · holds 50 AAPL');
  out(d('  Mandate: US equities and ETFs, max $25k per order, approval above $10k, GME denied, max 20% per position'));
  out('');
  const first = await send('Buy 10 MSFT (~$4,200)', { symbol: 'MSFT', qty: '10', side: 'buy', type: 'market', time_in_force: 'day' });
  await send('Buy 40 MSFT (~$16,800): needs approval', { symbol: 'MSFT', qty: '40', side: 'buy', type: 'market', time_in_force: 'day' });
  await send('Buy 120 NVDA (~$21,600): over 20% of equity', { symbol: 'NVDA', qty: '120', side: 'buy', type: 'limit', limit_price: '180', time_in_force: 'day' });
  await send('Buy 100 TSLA (~$40,000): over the limits', { symbol: 'TSLA', qty: '100', side: 'buy', type: 'market', time_in_force: 'day' });
  await send('Buy 5 GME: on the deny list', { symbol: 'GME', qty: '5', side: 'buy', type: 'market', time_in_force: 'day' });
  await send('Buy 0.01 BTC/USD: crypto not in the mandate', { symbol: 'BTC/USD', qty: '0.01', side: 'buy', type: 'market', time_in_force: 'gtc' });
  await send('Sell 50 AAPL: exit, always allowed', { symbol: 'AAPL', qty: '50', side: 'sell', type: 'market', time_in_force: 'day' });
  await send('Body changed after signing', { symbol: 'MSFT', qty: '1', side: 'buy', type: 'market', time_in_force: 'day' }, { tamper: true });
  await send('Same signed request sent twice', { symbol: 'MSFT', qty: '10', side: 'buy', type: 'market', time_in_force: 'day' }, { replay: first.headers });
  await send('Another agent using this mandate', { symbol: 'MSFT', qty: '1', side: 'buy', type: 'market', time_in_force: 'day' }, { key: rogue });
  registry.revokeKey(agent.kid);
  await send('After the agent key is revoked (kill switch)', { symbol: 'MSFT', qty: '1', side: 'buy', type: 'market', time_in_force: 'day' });

  const chain = verifyChain(evidence.entries);
  out('');
  out(`  Orders reaching the broker: ${filled} of 11 · evidence log: ${evidence.entries.length} entries, chain ${chain.ok ? g('intact') : r('BROKEN')}`);
  out('');
  proxy.close();
  broker.close();
  return chain.ok && filled === 2;
}
