# Mandate Protocol

**Signed orders for AI trading agents**

| | |
|---|---|
| Version | Draft 0.1 |
| Status | Working draft, open for comment |
| Date | 16 November 2026 |
| Editor | Shamaz Khan |
| Reference implementation | `mandate-protocol` (npm), this repository |
| Licence | Specification: CC BY 4.0. Code: Apache 2.0 |

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY and OPTIONAL are to be read as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.

---

## 1. Introduction

Brokers and trading platforms now let AI agents place orders on behalf of account holders, through REST APIs and Model Context Protocol (MCP) servers. Today an order from an agent looks the same as an order from any other API client. The broker cannot tell which agent sent it, who operates that agent, or what the account holder actually allowed it to do.

Mandate Protocol adds three things to every order an agent sends:

1. **Identity.** The agent signs the HTTP request with its own Ed25519 key, using HTTP Message Signatures (RFC 9421).
2. **Authority.** The request carries a *mandate*: a token, signed by an issuer the broker trusts, that states what this agent may do for this account.
3. **Accountability.** The verifier records every decision in a hash-chained evidence log.

A broker, MCP server or proxy that receives the order (the *verifier*) checks the signature, the agent's status in a public registry, and the order against the mandate. It returns **allow**, **deny** or **hold**. Verification is free and runs entirely in the verifier's own infrastructure.

### 1.1 Goals

- Any agent, on any model or framework, can sign orders with a few lines of code.
- Any broker can verify with a single function call and no network round trip in the common case.
- The account holder's limits travel with every order, so they are enforced the same way at every broker.
- Risk-reducing orders (exits) are never blocked by a mandate limit.
- Compatible with existing web standards: RFC 9421, RFC 9530, RFC 7515, RFC 7638, RFC 8032.

### 1.2 Non-goals

- Mandate does not hold funds, route orders or give investment advice.
- Mandate does not replace a broker's own risk controls or regulatory obligations. It gives the broker better information to apply them.
- Draft 0.1 does not define selective disclosure of mandate contents, multi-party approval or cross-broker aggregate limits. See section 13.

### 1.3 Terminology

| Term | Meaning |
|---|---|
| Account holder | The person or firm that owns the trading account. |
| Agent | Software that places orders for an account holder. Holds an Ed25519 private key. |
| Operator | The company or person that builds and runs the agent. |
| Issuer | A party that signs mandates for account holders, typically the broker or platform where the account holder grants access. |
| Verifier | The party that receives the agent's request and decides allow, deny or hold. Usually the broker API, an MCP server or a gateway in front of either. |
| Registry | A service that publishes agent and issuer public keys, their status and their assurance level. |
| Mandate | A signed token stating what one agent may do for one account. |
| Evidence log | An append-only, hash-chained record of the verifier's decisions. |

---

## 2. Overview

```
 Account holder ──grants──▶ Issuer ──signs mandate──▶ Agent
                                                       │
                     signed request + mandate header   │
                                                       ▼
 Registry ◀──key status── Verifier (broker / MCP server / gateway)
                              │
              allow ──▶ order goes to the broker as normal
              hold  ──▶ waits for the account holder's approval
              deny  ──▶ rejected with reason codes
              every decision ──▶ evidence log
```

1. The operator generates an Ed25519 key for the agent and registers the public key with a registry.
2. The account holder grants the agent access at an issuer. The issuer signs a mandate bound to that agent's key.
3. For every request, the agent signs the HTTP request (method, target URI, body digest and the mandate) and sends the mandate in the `Mandate` header.
4. The verifier checks the signature, resolves the agent and issuer keys in the registry, validates the mandate and evaluates the order against it.
5. The verifier records the decision in its evidence log and acts on it.

---

## 3. Keys and identifiers

### 3.1 Algorithm

All signatures in this version use **Ed25519** (RFC 8032). Keys are represented as JSON Web Keys (RFC 8037): `{"kty":"OKP","crv":"Ed25519","x":"<base64url>"}`.

### 3.2 Key identifier

The key identifier (`kid`) of a public key is its JWK thumbprint (RFC 7638) using SHA-256, base64url-encoded without padding. It is computed over the JSON object `{"crv":"Ed25519","kty":"OKP","x":"<x>"}` with members in that order and no whitespace.

Because the identifier is derived from the key, a verifier can check that a key matches its `kid` without trusting the registry for that binding.

### 3.3 Key roles

| Role | Signs | Registered as |
|---|---|---|
| Agent | HTTP requests | `type: "agent"` |
| Issuer | Mandates, and revocations of its own mandates | `type: "issuer"` |
| Verifier (optional) | Evidence log entries | `type: "verifier"` |

A key MUST be used for one role only.

---

## 4. The mandate

### 4.1 Format

A mandate is a JWS in compact serialisation (RFC 7515):

```
BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
```

The protected header MUST be:

```json
{ "alg": "EdDSA", "typ": "mandate+jws", "kid": "<issuer kid>" }
```

The payload is a JSON object:

| Member | Type | Required | Meaning |
|---|---|---|---|
| `v` | string | yes | Protocol version. `"0.1"` for this draft. |
| `mid` | string | yes | Unique mandate identifier, at least 16 characters of base64url. |
| `iss` | string | yes | Issuer `kid`. MUST equal the header `kid`. |
| `sub` | string | yes | Opaque account reference meaningful to the issuer and verifier, for example `acct_8341@quantl`. |
| `agent` | string | yes | The `kid` of the only agent key allowed to use this mandate. |
| `aud` | string[] | no | Verifier identifiers that may accept this mandate. If present, the verifier MUST find its own identifier in the list. |
| `iat` | integer | yes | Issued at, Unix seconds. |
| `nbf` | integer | no | Not valid before, Unix seconds. |
| `exp` | integer | yes | Expiry, Unix seconds. SHOULD be no more than 90 days after `iat`. |
| `policy` | object | yes | The limits. Section 5. |

The token MUST NOT exceed 8 KB.

### 4.2 Binding to the agent

The mandate is useless without the agent's private key: a verifier MUST reject a request whose signing key's `kid` differs from the mandate's `agent` member. A stolen mandate therefore cannot be replayed by a different agent.

### 4.3 Revocation

An issuer revokes a mandate by publishing its `mid` to a registry (section 8). A verifier MUST treat a revoked mandate as invalid for every order, including exits.

---

## 5. Policy

The `policy` object contains the limits the account holder has set. Every member is OPTIONAL; an absent member means "no limit from the mandate" for that dimension, and the broker's own controls still apply.

| Member | Type | Meaning |
|---|---|---|
| `instruments` | string[] | Allowed asset classes: `us_equity`, `etf`, `option`, `crypto`, `fx`, `future`, `bond`, `fund`. |
| `symbols.allow` | string[] | If present, only these symbols may be traded. Case-insensitive. |
| `symbols.deny` | string[] | These symbols may never be traded. Takes precedence over `allow`. |
| `sides` | string[] | Allowed sides: `buy`, `sell`. |
| `allow_short` | boolean | Whether the agent may open or increase a short position. Default `false`. |
| `order_types` | string[] | Allowed order types: `market`, `limit`, `stop`, `stop_limit`, `trailing_stop`. |
| `max_order_notional` | number | Largest single order, in `currency`. |
| `max_daily_notional` | number | Total notional of allowed orders per UTC day for this mandate. |
| `max_position_pct` | number | Largest position in one symbol after the order, as a percentage of account equity. |
| `max_leverage` | number | Largest gross exposure after the order, as a multiple of account equity. |
| `max_orders_per_minute` | integer | Rate limit for this mandate. |
| `require_approval.above_notional` | number | Orders above this notional are held for the account holder's approval. |
| `exits` | string | `"always_allow"` (default) or `"evaluate"`. |
| `currency` | string | ISO 4217 code for all notional values. Default `"USD"`. |

Example:

```json
{
  "instruments": ["us_equity", "etf"],
  "symbols": { "deny": ["GME", "AMC"] },
  "allow_short": false,
  "order_types": ["market", "limit"],
  "max_order_notional": 25000,
  "max_daily_notional": 100000,
  "max_position_pct": 5,
  "max_leverage": 1,
  "max_orders_per_minute": 30,
  "require_approval": { "above_notional": 10000 },
  "exits": "always_allow",
  "currency": "USD"
}
```

Verifiers MUST ignore unknown policy members in draft 0.1 and SHOULD log them. A future version will define a `crit` mechanism for members that must be understood.

---

## 6. Signed requests

### 6.1 Headers

An agent request carries:

| Header | Content |
|---|---|
| `Mandate` | The mandate token (section 4). |
| `Content-Digest` | SHA-256 digest of the body (RFC 9530), REQUIRED when the request has a body. |
| `Signature-Input` | RFC 9421 signature parameters, label `mandate`. |
| `Signature` | RFC 9421 signature, label `mandate`. |

### 6.2 Covered components

The signature MUST cover, in this order:

1. `"@method"`
2. `"@target-uri"`
3. `"content-digest"`, when the request has a body
4. `"mandate"`

It MAY cover additional components. A verifier MUST reject a signature that omits any required component.

### 6.3 Signature parameters

| Parameter | Required | Meaning |
|---|---|---|
| `created` | yes | Unix seconds when signed. |
| `expires` | yes | Unix seconds. MUST be no more than 300 seconds after `created`. |
| `keyid` | yes | The agent's `kid`. |
| `alg` | yes | `"ed25519"`. |
| `nonce` | yes | At least 128 bits of randomness, base64url. |
| `tag` | yes | `"mandate/0.1"`. |

Example (from `spec/test-vectors/v0.1.json`; the full mandate is in the vector file):

```
Mandate: eyJhbGciOiJFZERTQSIsInR5cCI6Im1hbmRhdGUrandzIiwia2lkIjoiVURE...
Content-Digest: sha-256=:yV+ij4ZFWnQPIYboGo2rPaFtnAzKTPGa0FnEZTJf6ic=:
Signature-Input: mandate=("@method" "@target-uri" "content-digest" "mandate");created=1763300100;expires=1763300160;keyid="aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU";alg="ed25519";nonce="bm9uY2Utdi0wLjEtdGVzdA";tag="mandate/0.1"
Signature: mandate=:NDS0KogTgKKwhi1+Szc3RrOx1WCwDzkstEgaToId3m2ZyZC96XzR38F5D3n/tw75dvDhbbBoRWFLVp5aZFRICQ==:
```

### 6.4 Signature base

The signature base is built exactly as in RFC 9421 section 2.5. For draft 0.1:

```
"@method": POST
"@target-uri": https://broker.example/v2/orders
"content-digest": sha-256=:yV+ij4ZFWnQPIYboGo2rPaFtnAzKTPGa0FnEZTJf6ic=:
"mandate": eyJhbGciOiJFZERTQSIsInR5cCI6Im1hbmRhdGUrandzIiwia2lkIjoiVURE...
"@signature-params": ("@method" "@target-uri" "content-digest" "mandate");created=1763300100;expires=1763300160;keyid="aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU";alg="ed25519";nonce="bm9uY2Utdi0wLjEtdGVzdA";tag="mandate/0.1"
```

Lines are separated by a single LF; there is no trailing LF.

### 6.5 Target URI behind proxies

`@target-uri` is the URI the agent sent the request to. A verifier behind a TLS terminator or gateway MUST reconstruct the original URI (scheme, host, path and query) before verifying, for example from `Forwarded` or from configuration.

---

## 7. Verification

### 7.1 Algorithm

A verifier processes a request in this order and stops at the first failure.

| Step | Check | Failure code |
|---|---|---|
| 1 | `Signature-Input` and `Signature` present with label `mandate` | `unsigned` |
| 2 | `alg` is `ed25519`, `tag` is `mandate/0.1` | `unsupported_alg` |
| 3 | Required components covered | `components_missing` |
| 4 | `created` not more than the allowed skew (default 60 s) in the future; `expires` not in the past; window at most 300 s | `signature_not_yet_valid`, `signature_expired` |
| 5 | `nonce` not seen within the window for this `keyid` | `replay` |
| 6 | `Content-Digest` matches the body | `digest_mismatch` |
| 7 | Agent key found in registry, `type` is `agent` | `agent_unknown` |
| 8 | Agent key status is `active` | `agent_revoked` |
| 9 | Agent assurance meets the verifier's minimum | `assurance_insufficient` |
| 10 | Signature valid over the signature base | `signature_invalid` |
| 11 | `Mandate` header present and is a well-formed JWS | `mandate_missing`, `mandate_invalid` |
| 12 | Issuer key found, `type` is `issuer`, status `active`, and trusted by this verifier | `issuer_unknown`, `issuer_revoked`, `issuer_untrusted` |
| 13 | Mandate signature valid | `mandate_invalid` |
| 14 | Mandate `agent` equals `keyid` | `mandate_agent_mismatch` |
| 15 | Mandate `aud`, if present, includes this verifier | `mandate_audience_mismatch` |
| 16 | Mandate not revoked | `mandate_revoked` |
| 17 | Order extracted from the request (section 7.3). A request to an order endpoint that the verifier cannot read is denied | `order_unreadable` |
| 18 | `nbf` and `exp` hold, unless the order is an exit | `mandate_not_yet_valid`, `mandate_expired` |
| 19 | Policy evaluation (section 7.2) | see 7.2 |

Failures in steps 1 to 18 result in **deny**.

### 7.2 Policy evaluation

If the request is not an order (for example reading positions), the verifier MAY allow it after steps 1 to 16.

If the order is an **exit** and the policy's `exits` is `always_allow`, the result is **allow** with reason `exit_always_allowed`; no further policy checks apply. An order is an exit when it only reduces an existing position: a sell of no more than the long quantity held, or a buy of no more than the short quantity held, in the same symbol.

Otherwise every rule is evaluated and every failure recorded:

| Rule | Result | Code |
|---|---|---|
| Asset class not in `instruments` | deny | `instrument_not_allowed` |
| Symbol in `symbols.deny` | deny | `symbol_denied` |
| `symbols.allow` present and symbol not in it | deny | `symbol_not_allowed` |
| Side not in `sides` | deny | `side_not_allowed` |
| Sell would open or increase a short and `allow_short` is not `true` | deny | `short_not_allowed` |
| Order type not in `order_types` | deny | `order_type_not_allowed` |
| Notional above `max_order_notional` | deny | `order_notional_exceeded` |
| Day's notional plus this order above `max_daily_notional` | deny | `daily_notional_exceeded` |
| Position after the order above `max_position_pct` of equity | deny | `position_limit_exceeded` |
| Gross exposure after the order above `max_leverage` × equity | deny | `leverage_exceeded` |
| Orders in the last 60 s at or above `max_orders_per_minute` | deny | `rate_limit_exceeded` |
| Notional above `require_approval.above_notional` | hold | `approval_required` |
| Notional cannot be determined but a notional rule applies | hold | `notional_unknown` |
| Account context needed but unavailable | hold | `context_unavailable` |

The result is **deny** if any rule denies, otherwise **hold** if any rule holds, otherwise **allow**. The verifier MUST report every code, not only the first.

Notional is the order's stated notional if present; otherwise quantity × limit price for limit orders, or quantity × the verifier's reference price.

A verifier MUST NOT count held or denied orders towards `max_daily_notional`. It counts held orders when they are approved.

### 7.3 Order extraction

Verifiers map their own order format to a normalised order:

| Member | Meaning |
|---|---|
| `symbol` | Instrument symbol, upper case. |
| `side` | `buy` or `sell`. |
| `qty` | Quantity, if given. |
| `notional` | Notional value, if given. |
| `type` | Order type. |
| `limit_price`, `stop_price` | If given. |
| `asset_class` | One of the values in section 5. |

The reference implementation includes mappings for the Alpaca Trading API, for MCP `tools/call` requests and for requests that already use the normalised form.

### 7.4 Responses

This draft does not change the broker's success response. When a verifier denies or holds, it SHOULD respond:

- **deny:** HTTP 403, `Content-Type: application/json`, body `{"error":"mandate_denied","reasons":[...],"evidence_id":"..."}`.
- **hold:** HTTP 202, body `{"status":"held","approval_id":"...","reasons":[...],"evidence_id":"..."}`.

On allow it SHOULD add the response header `Mandate-Decision: allow; evidence="<id>"`.

---

## 8. Registry

### 8.1 Records

```json
{
  "kid": "aVBtapLd11SUVKIMGJfPzOEDuN0sXcmzJQNVT-_sKEU",
  "type": "agent",
  "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q" },
  "name": "momentum-bot",
  "operator": { "name": "Acme Quant", "url": "https://acme.example" },
  "status": "active",
  "assurance": "basic",
  "created_at": 1763300000
}
```

`status` is `active` or `revoked`. `assurance` is one of:

| Level | Meaning |
|---|---|
| `basic` | Key registered with proof of possession. Free. |
| `verified` | The operator's identity has been checked by the registry. |
| `preflight` | Verified, and the agent version has passed a published adversarial test. The record carries a `preflight` object with `report_url`, `agent_version` and `expires_at`. |

### 8.2 HTTP API

| Method and path | Purpose |
|---|---|
| `GET /.well-known/mandate-registry` | Registry metadata: `{"protocol":"mandate/0.1","api":"/v0"}` |
| `GET /v0/keys/{kid}` | Key record, or 404 |
| `POST /v0/keys` | Register a key (8.3) |
| `POST /v0/keys/{kid}/revoke` | Revoke a key (8.3) |
| `POST /v0/keys/{kid}/assurance` | Set assurance level (registry operator only) |
| `GET /v0/mandates/{mid}` | `{"mid":"...","status":"active"|"revoked"}` |
| `POST /v0/mandates/{mid}/revoke` | Revoke a mandate (8.3) |
| `GET /v0/revocations?since={unix}` | Revocations since a time, for verifier caches |

### 8.3 Proof of possession

Requests that change a key's state carry a proof signed by the relevant private key:

```json
{ "proof": { "ts": 1763300000, "sig": "<base64url Ed25519 signature>" } }
```

The signed message is the canonical JSON (keys sorted, no whitespace) of `{"op":"<op>","kid":"<kid>","ts":<ts>}`, where `op` is `register` or `revoke`; for mandate revocation it is `{"op":"revoke_mandate","mid":"<mid>","kid":"<issuer kid>","ts":<ts>}`. The registry MUST reject a proof whose `ts` is more than 300 seconds from its own clock.

Registries SHOULD allow open registration of `agent` keys at `basic` assurance and SHOULD require operator approval for `issuer` keys.

### 8.4 Caching

Verifiers SHOULD cache key records for no more than 60 seconds and SHOULD poll `/v0/revocations` at least every 10 seconds, so that a revocation (the kill switch) takes effect everywhere within seconds. The reference implementation polls every 5 seconds. A verifier MAY run fully offline with a static set of trusted keys.

---

## 9. Evidence log

Each decision is one JSON object, appended to a log (for example JSON Lines):

| Member | Meaning |
|---|---|
| `v` | `"0.1"` |
| `seq` | Sequence number, starting at 1 |
| `ts` | Unix milliseconds |
| `prev` | `hash` of the previous entry, or `"0"` for the first |
| `decision` | `allow`, `deny` or `hold` |
| `reasons` | Reason codes |
| `agent`, `assurance`, `operator` | Agent `kid` and registry details, if resolved |
| `mandate`, `sub`, `issuer` | Mandate `mid`, account reference and issuer `kid`, if resolved |
| `order` | The normalised order, if any |
| `request` | `method`, `target` and `content_digest` |
| `verifier` | Verifier identifier |
| `hash` | base64url SHA-256 of the canonical JSON of all other members |
| `sig` | OPTIONAL. Ed25519 signature over `hash` by the verifier's key |

Anyone holding the log can check that no entry was changed, removed or inserted by recomputing the chain. Signed entries additionally prove which verifier wrote them.

The log MUST NOT contain the mandate token, signatures or request bodies beyond the normalised order.

---

## 10. Security considerations

- **Key compromise.** Operators SHOULD keep agent keys in a secrets manager or KMS and rotate them. Revocation in the registry is the kill switch; verifiers honour it within their polling interval.
- **Replay.** Prevented by `created`, `expires` and `nonce`. Verifiers that run several instances SHOULD share nonce state, or keep the window short.
- **Prompt injection.** A compromised agent can only sign orders that its mandate allows. Mandate limits the damage an injected instruction can do; it does not prevent the injection.
- **Mandate theft.** Useless without the bound agent key (section 4.2).
- **Exits.** Always allowing risk-reducing orders means an agent cannot be trapped in a position by its own limits. It also means a compromised agent can close positions. Account holders who need otherwise can set `exits` to `evaluate`.
- **Clock skew.** Verifiers SHOULD use NTP and keep the default skew at 60 seconds.
- **Privacy.** Mandates reveal the account holder's limits to every verifier that sees them. Use `aud` to restrict where a mandate is accepted, and opaque `sub` values.
- **Registry trust.** A verifier chooses which registries and issuers it trusts. Key identifiers are self-certifying (section 3.2), so a registry cannot substitute a different key for a known `kid`.

---

## 11. Conformance

- An **agent** conforms if it signs requests as in section 6 and sends a valid mandate.
- A **verifier** conforms if it implements section 7 in full, including reporting all policy reason codes and recording evidence as in section 9.
- A **registry** conforms if it implements the endpoints and proof checks in section 8.

Test vectors are in `spec/test-vectors/`.

---

## 12. Relationship to other work

- **HTTP Message Signatures (RFC 9421)** provide the request signature. Mandate fixes the components and parameters so any two implementations interoperate.
- **Web Bot Auth** and the **Visa Trusted Agent Protocol** use the same RFC 9421 approach to identify agents to merchants. Mandate applies it to trading orders and adds the account holder's limits.
- **OAuth 2.0** authorises an application to an account. Mandate sits alongside it: OAuth says the application may trade; the mandate says how much, in what, and that this particular agent is the one doing it.

---

## 13. Open questions for draft 0.2

1. Selective disclosure of policy members (for example SD-JWT) so a verifier sees only what it needs.
2. Approval flows: a standard way for the account holder to approve a held order and for the verifier to release it.
3. Limits across brokers: whether daily notional can be enforced across verifiers without sharing account data.
4. A `crit` list for policy members that must be understood.
5. Delegation chains: an agent that delegates to sub-agents with narrower mandates.
6. Post-quantum signature agility.

Comments: open an issue with the label `spec`.

---

## Appendix A. Reason codes

`unsigned`, `unsupported_alg`, `components_missing`, `signature_not_yet_valid`, `signature_expired`, `replay`, `digest_mismatch`, `agent_unknown`, `agent_revoked`, `assurance_insufficient`, `signature_invalid`, `mandate_missing`, `mandate_invalid`, `issuer_unknown`, `issuer_revoked`, `issuer_untrusted`, `mandate_agent_mismatch`, `mandate_audience_mismatch`, `mandate_revoked`, `mandate_not_yet_valid`, `mandate_expired`, `instrument_not_allowed`, `symbol_denied`, `symbol_not_allowed`, `side_not_allowed`, `short_not_allowed`, `order_type_not_allowed`, `order_notional_exceeded`, `daily_notional_exceeded`, `position_limit_exceeded`, `leverage_exceeded`, `rate_limit_exceeded`, `approval_required`, `notional_unknown`, `context_unavailable`, `exit_always_allowed`, `not_an_order`, `order_unreadable`.

## Appendix B. References

- RFC 2119, RFC 8174: requirement key words
- RFC 7515: JSON Web Signature
- RFC 7638: JWK Thumbprint
- RFC 8032: Ed25519
- RFC 8037: CFRG curves in JOSE
- RFC 8941: Structured Field Values for HTTP
- RFC 9421: HTTP Message Signatures
- RFC 9530: Digest Fields
