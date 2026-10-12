# Delivery / claim ceiling

## Implemented in 0.2 (local reference, tested)

- **Contracts:** versioned JSON Schemas (`schemas/*.v1.schema.json`) generated from
  the strict models with drift checks; precise signature/canonicalization/chain
  specification ([SPEC-SIGNATURES.md](SPEC-SIGNATURES.md)); deterministic
  cross-language vectors; dependency-free JavaScript verifier and signer that
  pytest runs against the Python implementation.
- **Policy:** declarative `autheo.policy/v1` (YAML/JSON) — scope/tool/resource
  allow+deny globs, windowed and lifetime budgets, rate limits, time windows,
  escalation rules, per-check explanations, policy digest on every receipt.
  The default policy reproduces 0.1 outcomes and reason codes
  ([POLICY.md](POLICY.md)).
- **Ledger:** per-environment SQLite ledgers of signed, hash-chained receipts;
  persistent mode adds append-only triggers; a non-raising verifier reports the
  first bad row and checks an externally stored anchor head; receipts for
  decisions, executor-reported outcomes, revocations, identity issuance,
  mandate grants and handoffs.
- **Service surfaces:** persistent state directory (local-dev file keys), local
  HTTP API on loopback with bearer-token auth and OpenAPI 3.1, full CLI
  (`python -m autheo_agent_environment`), and the browser demo rebuilt on the API
  ([API-AND-CLI.md](API-AND-CLI.md)).
- Still present from 0.1: signed passports/mandates/requests, strict DEMO
  accounting, idempotency, concurrency-safe reservations, destination-bound
  checkpoint import, short-lived read-only MCP snapshot export.

## Not implemented (do not claim)

- No DID method, verifiable credential, wallet, payment, THEO transfer, chain
  anchoring, or connection to any Autheo platform service.
- No production key custody: issuer and server-held agent keys are unencrypted
  local files. No HSM/KMS, rotation or issuer rollover.
- No human approval workflow: `escalate` stays pending.
- No TLS, multi-tenant isolation, hosted deployment, replication or HA.
- No executor: Autheo never runs an action; outcome receipts are executor claims.
- JARVIS and Paperclip: integration notes and tested reference JS code only; no
  changes or end-to-end runs in those projects ([INTEGRATIONS.md](INTEGRATIONS.md)).
- MCP branch: unchanged five read-only inspection tools; snapshot format unchanged.
- Existing website: unchanged; it must not advertise this prototype as deployed.

Verification results are recorded in [VERIFICATION.md](VERIFICATION.md).

## Planned direction

The product-level DID, Agent Guardrail Interface, defense-in-depth, Autheo
ecosystem mapping, Hyperliquid adapter example, decision questions, and staged
acceptance gates are documented in [PRODUCT-PLAN.md](PRODUCT-PLAN.md). These are
proposed work, not implemented capabilities. See the
[north-star architecture](AUTHEO-AGENT-TRUST-ARCHITECTURE.svg).
