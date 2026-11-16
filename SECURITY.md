# Security policy

Mandate sits in the path of real orders. We take reports seriously and respond quickly.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. We aim to acknowledge within 2 working days and to agree a fix and disclosure date with you within 10.

## Scope

In scope: the specification (`spec/`), this package, the reference registry and proxy. Examples include signature bypasses, mandate forgery or confusion, replay, policy evaluation errors that allow an order the mandate forbids, evidence log tampering that goes undetected, and registry proof bypasses.

Out of scope: denial of service by volume against a self-hosted instance, issues that need a compromised agent or issuer private key, and third-party broker APIs.

## Supported versions

Security fixes are released for the latest minor version of the current major.

## Deployment notes

- Keep agent and issuer private keys in a secrets manager or KMS, never in source control.
- Run verifiers with NTP-synchronised clocks.
- Several verifier instances behind a load balancer should share replay state (implement `StateStore`) or keep signature lifetimes short.
- Configure `trustedIssuers`; do not accept mandates from every registered issuer in production.
