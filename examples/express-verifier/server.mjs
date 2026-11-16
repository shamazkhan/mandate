// A broker API verifying Mandate-signed orders with Express.
// npm i express mandate-protocol
import express from 'express';
import { createVerifier, mandateMiddleware } from 'mandate-protocol/verifier';
import { RegistryClient } from 'mandate-protocol/registry';
import { alpacaAdapter } from 'mandate-protocol/adapters';
import { EvidenceLog } from 'mandate-protocol/evidence';

const verifier = createVerifier({
  id: 'api.mybroker.example',
  registry: new RegistryClient({ url: process.env.MANDATE_REGISTRY ?? 'http://localhost:8787' }),
  trustedIssuers: (process.env.MANDATE_TRUSTED_ISSUERS ?? '').split(',').filter(Boolean),
  adapter: alpacaAdapter(), // or genericAdapter() / mcpAdapter(), or your own
  evidence: new EvidenceLog({ file: 'evidence.jsonl' }),
  // Your own account data: equity, positions and reference prices for the account in mandate.sub.
  context: async ({ mandate }) => loadAccount(mandate.sub),
});

const app = express();
// Verify before any JSON parser so the exact signed bytes are checked.
app.post('/v2/orders', mandateMiddleware(verifier, { trustProxy: true }), (req, res) => {
  const order = JSON.parse(req.rawBody.toString('utf8'));
  // req.mandate has the decision, agent record, mandate and normalised order.
  res.json({ id: 'ord_' + Date.now(), status: 'accepted', symbol: order.symbol, agent: req.mandate.agent.kid });
});

app.listen(3000, () => console.log('broker API on http://localhost:3000'));

async function loadAccount(sub) {
  return { equity: 100_000, positions: {}, prices: { AAPL: 230, MSFT: 420 } };
}
