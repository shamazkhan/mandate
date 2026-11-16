# Mandate

**Signed orders for AI trading agents.**

[![CI](https://github.com/shamazkhan/mandate/actions/workflows/ci.yml/badge.svg)](https://github.com/shamazkhan/mandate/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/mandate-protocol?color=2BFF88&labelColor=0B0B0A)](https://www.npmjs.com/package/mandate-protocol)
[![spec](https://img.shields.io/badge/spec-draft%200.1-2BFF88?labelColor=0B0B0A)](spec/SPEC.md)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-black)](LICENSE)

Brokers now let AI agents trade through APIs and MCP servers. Today the broker can't tell which agent sent an order, who runs it, or what the account holder actually allowed it to do.

Mandate fixes that the way HTTPS fixed websites:

- **The agent signs every order** with its own key (HTTP Message Signatures, RFC 9421).
- **The account holder's limits travel with the order** as a signed *mandate*: instruments, order size, daily total, position size, leverage, approval thresholds.
- **The broker verifies for free**, in one call, and gets **allow**, **deny** or **hold**, with every decision written to a tamper-evident log.
- **Exits are never blocked.** An agent can always close a position.
- **One registry call revokes an agent everywhere.** That's the kill switch.

```
agent ──signed order + mandate──▶ verifier (broker API / MCP server / proxy) ──allow──▶ broker
                                       │
                                       ├── hold ──▶ account holder approves
                                       ├── deny ──▶ reason codes, never reaches the broker
                                       └── evidence log (hash-chained)
```

Zero runtime dependencies. Node 20+. Apache 2.0.

## See it in 10 seconds

```bash
npx mandate-protocol demo
```

```
  ALLOW  Buy 10 MSFT (~$4,200)                        filled as ord_1
  HOLD   Buy 40 MSFT (~$16,800): needs approval       approval_required
  DENY   Buy 120 NVDA (~$21,600): over 20% of equity  position_limit_exceeded, approval_required
  DENY   Buy 100 TSLA (~$40,000): over the limits     order_notional_exceeded, position_limit_exceeded, approval_required
  DENY   Buy 5 GME: on the deny list                  symbol_denied
  DENY   Buy 0.01 BTC/USD: crypto not in the mandate  instrument_not_allowed
  ALLOW  Sell 50 AAPL: exit, always allowed           filled as ord_2
  DENY   Body changed after signing                   digest_mismatch
  DENY   Same signed request sent twice               replay
  DENY   Another agent using this mandate             mandate_agent_mismatch
  DENY   After the agent key is revoked (kill switch) agent_revoked

  Orders reaching the broker: 2 of 11 · evidence log: 11 entries, chain intact
```

## Install

```bash
npm install mandate-protocol
```

## For agent builders: sign your orders

```js
import { createAgent } from 'mandate-protocol/agent';

const agent = createAgent({ key: agentKeyFile, mandate: mandateToken });

// Same as fetch(), but signed. Works with any broker that verifies Mandate.
const res = await agent.fetch('https://broker.example/v2/orders', {
  json: { symbol: 'AAPL', qty: '1', side: 'buy', type: 'market', time_in_force: 'day' },
  headers: { 'APCA-API-KEY-ID': '...', 'APCA-API-SECRET-KEY': '...' },
});
```

Or get the headers and add them to your own HTTP client: `agent.sign({ method, url, body })`.

Create a key and register it (free):

```bash
mandate keygen --type agent --out agent.key.json
mandate registry register --url https://registry.example --key agent.key.json --name my-bot --operator "My Company"
```

## For brokers and MCP servers: verify for free

```js
import { createVerifier, mandateMiddleware } from 'mandate-protocol/verifier';
import { RegistryClient } from 'mandate-protocol/registry';
import { alpacaAdapter } from 'mandate-protocol/adapters';

const verifier = createVerifier({
  id: 'api.mybroker.example',
  registry: new RegistryClient({ url: 'https://registry.example' }),
  trustedIssuers: ['<your issuer kid>'],
  adapter: alpacaAdapter(),                       // or mcpAdapter(), genericAdapter(), or your own
  context: ({ mandate }) => loadAccount(mandate.sub), // equity, positions, prices
});

app.post('/v2/orders', mandateMiddleware(verifier), placeOrder);
```

Not on Express? `await verifier.verify({ method, url, headers, body })` returns `{ decision, reasons, agent, mandate, order, evidence }`. For Workers, Next.js, Hono, Deno or Bun use `verifyFetchRequest(verifier, request)`.

### Or put a proxy in front of an existing API

No code changes to the broker:

```bash
mandate proxy --upstream https://paper-api.alpaca.markets --registry https://registry.example --port 8788
```

Allowed orders are forwarded with the Mandate headers removed. Denied orders never reach the broker. Held orders wait at `/_mandate/holds` for approval. See [examples/alpaca-paper](examples/alpaca-paper).

## For platforms: issue mandates

The platform where the account holder grants an agent access signs the mandate:

```bash
mandate keygen --type issuer --out issuer.key.json
mandate issue --issuer issuer.key.json --agent <agent kid> --sub acct_123 --policy policy.json --ttl 30d
```

```json
{
  "instruments": ["us_equity", "etf"],
  "symbols": { "deny": ["GME"] },
  "order_types": ["market", "limit"],
  "max_order_notional": 25000,
  "max_daily_notional": 100000,
  "max_position_pct": 5,
  "max_leverage": 1,
  "max_orders_per_minute": 30,
  "require_approval": { "above_notional": 10000 },
  "exits": "always_allow"
}
```

A mandate is bound to one agent key. A stolen mandate is useless without that key.

## What the verifier checks

1. The signature covers the method, URL, body digest and mandate, is fresh (60 s by default) and hasn't been used before.
2. The agent's key is registered, active, and at the assurance level the broker requires.
3. The mandate was signed by an issuer the broker trusts, for this agent, for this broker, and hasn't expired or been revoked.
4. The order fits the mandate. **Every** failing rule is reported, not just the first.

Full rules and reason codes: [spec section 7](spec/SPEC.md#7-verification).

## Run a registry

```bash
MANDATE_ADMIN_TOKEN=... mandate registry serve --port 8787 --data registry.json
```

Agents register themselves at `basic` assurance with proof of key possession. Issuer keys and higher assurance levels (`verified`, `preflight`) are set by the registry operator. Verifiers cache keys for 60 seconds but poll the revocation feed every 5 seconds, so a revoked agent stops everywhere within seconds.

## Command line

| Command | What it does |
|---|---|
| `mandate demo` | The whole protocol locally |
| `mandate keygen` | Ed25519 key for an agent, issuer or verifier |
| `mandate issue` | Sign a mandate |
| `mandate inspect` | Decode a mandate |
| `mandate sign` | Headers (or a curl command) for a signed request |
| `mandate proxy` | Verifying reverse proxy |
| `mandate registry serve / register / revoke / revoke-mandate / assurance` | Run or use a registry |
| `mandate evidence verify` | Check an evidence log's hash chain |

## Package layout

| Import | Contents |
|---|---|
| `mandate-protocol` | Everything below, plus keys, mandates, signatures and the policy engine |
| `mandate-protocol/agent` | `createAgent`: sign requests and signed `fetch` |
| `mandate-protocol/verifier` | `createVerifier`, Express/Connect middleware, fetch `Request` binding |
| `mandate-protocol/registry` | Registry client (cached), static registry, reference server |
| `mandate-protocol/adapters` | Alpaca, MCP `tools/call` and generic order mappings |
| `mandate-protocol/proxy` | Verifying reverse proxy and Alpaca account context |
| `mandate-protocol/evidence` | Hash-chained evidence log and chain verification |

## Specification

[Mandate Protocol draft 0.1](spec/SPEC.md) with [JSON schemas](spec/schemas) and [test vectors](spec/test-vectors). It builds on RFC 9421, RFC 9530, RFC 7515, RFC 7638 and RFC 8032, and uses the same signing approach as Web Bot Auth, so agents that already sign for the web can sign orders the same way.

Draft 0.1 is open for comment: open an issue with the `spec` label.

## Security

Mandate limits what a compromised or prompt-injected agent can do; it does not stop the compromise. Keep agent keys in a secrets manager. Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOVERNANCE.md](GOVERNANCE.md). Code is Apache 2.0; the specification is CC BY 4.0.

Mandate does not hold funds, route orders or give investment advice.
