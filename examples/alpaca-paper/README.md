# Alpaca paper trading, end to end

Put a Mandate verifying proxy in front of Alpaca's paper API, then point an agent at the proxy. Allowed orders reach Alpaca; denied orders never do; held orders wait for approval.

You need an Alpaca paper account (free) and its API key ID and secret.

```bash
npm i -g mandate-protocol

# 1. Keys: one issuer (the platform where the account holder grants access) and one agent
mandate keygen --type issuer --out issuer.key.json
mandate keygen --type agent  --out agent.key.json

# 2. Mandate: what this agent may do on this account
AGENT_KID=$(node -p "require('./agent.key.json').kid")
mandate issue --issuer issuer.key.json --agent "$AGENT_KID" --sub acct_paper_1 \
  --policy ../policy.json --ttl 30d > mandate.jws

# 3. The verifier, trusting these two public keys (no registry needed for a local test)
export MANDATE_ADMIN_TOKEN=change-me
mandate proxy --upstream https://paper-api.alpaca.markets --trust issuer.key.json,agent.key.json --port 8788
```

In another terminal:

```bash
export APCA_API_KEY_ID=...  APCA_API_SECRET_KEY=...
node agent.mjs
```

Held orders:

```bash
curl -s localhost:8788/_mandate/holds -H "authorization: Bearer change-me"
curl -s -X POST localhost:8788/_mandate/holds/<id>/approve -H "authorization: Bearer change-me"
```

Every decision is appended to `evidence.jsonl`. Check it with `mandate evidence verify evidence.jsonl`.

With a shared registry instead of local key files, register the agent with `mandate registry register --url <registry> --key agent.key.json` and start the proxy with `--registry <url>` instead of `--trust`.
