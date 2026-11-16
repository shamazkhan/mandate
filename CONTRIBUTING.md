# Contributing

Thanks for helping. There are two kinds of contribution: changes to the **specification** and changes to the **code**.

## Specification changes

The spec lives in `spec/SPEC.md`. Draft 0.1 is open for comment.

1. Open an issue with the `spec` label describing the problem before proposing text. Say which section it affects and why the current text is not enough.
2. Proposals that change what goes over the wire need a test vector update (`npm run vectors`) and a note on compatibility.
3. Changes are decided as described in [GOVERNANCE.md](GOVERNANCE.md).

## Code changes

```bash
git clone https://github.com/shamazkhan/mandate && cd mandate
npm install
npm test          # type-checks and runs the full suite
npm run demo      # end-to-end check
```

- Keep zero runtime dependencies. Node's built-in `crypto`, `http` and `node:test` are enough.
- Every behaviour change needs a test. Security fixes need a test that fails without the fix.
- Keep the code and `spec/SPEC.md` in step. If they disagree, the spec wins and the code is a bug.
- Use clear reason codes and messages; brokers show them to their users.
- Commit messages: short imperative summary, then why.

## Adapters

New broker or MCP adapters are welcome in `src/adapters/`. An adapter maps a request to the normalised order (spec section 7.3) and must return `unreadable` rather than guessing when it cannot read an order request.

## Licence

By contributing you agree that your code is licensed under Apache 2.0 and your specification text under CC BY 4.0.

## Repository layout

```
spec/
  SPEC.md                 Mandate Protocol draft 0.1
  schemas/                JSON schemas: policy, mandate payload, order, key record, evidence entry
  test-vectors/v0.1.json  Deterministic conformance vector (regenerate with npm run vectors)
src/
  core/                   Keys (Ed25519, RFC 7638), structured fields (RFC 8941), signatures (RFC 9421),
                          Content-Digest (RFC 9530), mandate tokens (JWS), policy engine
  agent/                  Agent SDK: sign requests, signed fetch
  verifier/               Verification algorithm, replay and usage state, middleware
  adapters/               Broker request → normalised order (Alpaca, MCP, generic)
  registry/               Registry client, static registry, reference server
  evidence/               Hash-chained evidence log
  proxy/                  Verifying reverse proxy, Alpaca account context
  cli/                    The mandate command and demo
test/                     node:test suites, including RFC and conformance vectors
examples/                 Alpaca paper trading, Express verifier, example policy
scripts/vectors.mjs       Test vector generator
.github/                  CI, release (npm with provenance), CodeQL, Dependabot, templates
```
