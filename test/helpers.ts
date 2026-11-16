import { generateKey } from '../src/core/keys.js';
import { issueMandate } from '../src/core/mandate.js';
import { StaticRegistry } from '../src/registry/static.js';
import { createVerifier, type VerifierOptions } from '../src/verifier/index.js';
import { alpacaAdapter } from '../src/adapters/index.js';
import { signRequest } from '../src/core/signature.js';
import type { AccountContext, Policy } from '../src/core/types.js';

export const URL_ORDERS = 'https://broker.example/v2/orders';

export const ACCOUNT: AccountContext = {
  equity: 100_000,
  positions: { AAPL: { qty: 50, market_value: 11_500, price: 230 } },
  prices: { MSFT: 400, TSLA: 400, GME: 25 },
};

export const POLICY: Policy = {
  instruments: ['us_equity', 'etf'],
  symbols: { deny: ['GME'] },
  order_types: ['market', 'limit'],
  max_order_notional: 25_000,
  max_daily_notional: 30_000,
  max_position_pct: 20,
  max_orders_per_minute: 3,
  require_approval: { above_notional: 10_000 },
};

export function setup(policy: Policy = POLICY, vopts: Partial<VerifierOptions> = {}, mopts: { aud?: string[]; ttl?: number; iat?: number } = {}) {
  const issuer = generateKey('issuer');
  const agent = generateKey('agent');
  const registry = new StaticRegistry();
  registry.add(issuer);
  registry.add(agent, { operator: { name: 'Acme' } });
  const mandate = issueMandate({ issuer, agent: agent.kid, sub: 'acct_1', policy, ...mopts });
  const verifier = createVerifier({ registry, id: 'broker.example', adapter: alpacaAdapter(), context: () => ACCOUNT, ...vopts });
  const order = (o: Record<string, unknown>, key = agent, url = URL_ORDERS, m = mandate) => {
    const body = JSON.stringify({ time_in_force: 'day', type: 'market', ...o });
    const headers = signRequest({ method: 'POST', url, body, mandate: m, key });
    return { method: 'POST', url, headers: { ...headers, 'content-type': 'application/json' } as Record<string, string>, body };
  };
  return { issuer, agent, registry, mandate, verifier, order };
}

export const codes = (r: { reasons: { code: string }[] }) => r.reasons.map((x) => x.code);
