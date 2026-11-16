// An agent placing orders through the Mandate proxy in front of Alpaca paper trading.
import { readFileSync } from 'node:fs';
import { createAgent } from 'mandate-protocol/agent';

const agent = createAgent({
  key: JSON.parse(readFileSync('agent.key.json', 'utf8')),
  mandate: readFileSync('mandate.jws', 'utf8').trim(),
});

const alpaca = {
  'APCA-API-KEY-ID': process.env.APCA_API_KEY_ID,
  'APCA-API-SECRET-KEY': process.env.APCA_API_SECRET_KEY,
};
const BASE = process.env.MANDATE_PROXY ?? 'http://localhost:8788';

async function order(o) {
  const res = await agent.fetch(`${BASE}/v2/orders`, { json: { time_in_force: 'day', type: 'market', ...o }, headers: alpaca });
  const body = await res.json();
  const decision = res.status === 202 ? 'HOLD' : res.ok ? 'ALLOW' : res.status === 403 ? 'DENY' : `HTTP ${res.status}`;
  console.log(decision.padEnd(6), JSON.stringify(o), body.reasons?.map((r) => r.code).join(', ') ?? body.id ?? body.message ?? '');
}

await order({ symbol: 'AAPL', qty: '1', side: 'buy' });        // allowed, within limits
await order({ symbol: 'MSFT', notional: '15000', side: 'buy' }); // held: above the approval threshold
await order({ symbol: 'GME', qty: '1', side: 'buy' });          // denied: on the deny list
await order({ symbol: 'BTC/USD', qty: '0.001', side: 'buy', time_in_force: 'gtc' }); // denied: crypto not in mandate
