# Changelog

All notable changes to this project are documented here. The package follows semantic versioning; the protocol version is tracked separately in `spec/SPEC.md`.

## 1.0.0 (2026-11-16)

First public release. Reference implementation of Mandate Protocol draft 0.1.

### Protocol
- Signed requests: RFC 9421 HTTP Message Signatures with Ed25519, covering method, target URI, Content-Digest (RFC 9530) and the mandate; `created`, `expires`, `nonce` and `tag="mandate/0.1"`.
- Mandates: compact JWS (EdDSA, `typ: mandate+jws`) bound to one agent key, with audience, validity window and revocation.
- Policy: instruments, symbol allow and deny lists, sides, short selling, order types, order and daily notional, position percentage, leverage, rate limit, approval threshold. Exits always allowed by default.
- Verification algorithm with 38 reason codes; every failing policy rule is reported.
- Registry API with proof of possession, assurance levels (`basic`, `verified`, `preflight`) and revocation feed.
- Hash-chained evidence log with optional verifier signatures.
- JSON schemas and deterministic test vectors.

### Package
- `mandate-protocol/agent`: key handling, request signing, signed `fetch`.
- `mandate-protocol/verifier`: verifier, Express/Connect middleware, WHATWG `Request` binding, replay and usage state.
- `mandate-protocol/registry`: cached HTTP client, static registry, reference server.
- `mandate-protocol/adapters`: Alpaca Trading API, MCP `tools/call`, generic.
- `mandate-protocol/proxy`: verifying reverse proxy with held-order approval, Alpaca account context.
- `mandate-protocol/evidence`: evidence log and chain verification.
- `mandate` CLI: `demo`, `keygen`, `issue`, `inspect`, `sign`, `proxy`, `registry`, `evidence verify`.
- Zero runtime dependencies.
