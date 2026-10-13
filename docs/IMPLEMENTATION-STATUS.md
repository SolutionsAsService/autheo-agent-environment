# Delivery / claim ceiling

## Experimental in 0.4 (post-quantum agility, tested, not a stable contract)

- `pqc.py`: ML-DSA-44 (FIPS 204, via `cryptography`/OpenSSL 3.5) did:key
  (multicodec 0x1210, draft), the `mldsa44-jcs-2024` Data Integrity cryptosuite
  (W3C CCG quantum-safe draft), hybrid proof sets `[eddsa-jcs-2022,
  mldsa44-jcs-2024]`, self-issued cross-signed `AutheoKeyBinding` credentials,
  and verifier policies `classical` / `hybrid` / `pq` (stripping, unbound keys,
  tampering, wrong purpose and duplicate suites are rejected).
- `tests/vectors/autheo-v3-pq-vectors.json` (verify-only, ML-DSA is randomised)
  checked by Python and by `interop/js/autheo-pqc.mjs` on Node >= 24.
- **Not yet**: hybrid proofs inside delegation chains, invocations, revocations
  or receipts; ML-KEM; browser ML-DSA verification; CLI/API surface. v2 bytes are
  unchanged. Plan: [PQC-ROADMAP.md](PQC-ROADMAP.md).

## Implemented in 0.3 (v2: permissionless DID delegation, tested)

- **DIDs:** did:key (Ed25519 Multikey) for every agent, principal and environment, created
  offline with no registration; DID documents; v1 key ids map to the same key's did:key;
  did:web resolution offline by default (cache/pinned documents; HTTPS fetch only if enabled -
  never tested live).
- **Delegation:** W3C VC 2.0 `AutheoDelegation` credentials signed with Data Integrity
  `eddsa-jcs-2022`; chains of up to 10 links bound by parent id + digest; attenuation of
  environments/scopes/resources/tools/budgets/validity/depth enforced by issuers and verifiers;
  signed revocation records (issuer/ancestor/subject), distributed via revocation lists, ledger
  exports and bundles.
- **Offline verification:** `python -m autheo_agent_environment.verifier` (bundle, chain,
  invocation, ledger) and the dependency-free isomorphic `interop/js/autheo-did.mjs` verify a
  decision and its whole chain back to a pinned root DID with no network or service.
- **Policy decision point:** invocations are verified, chains checked against trusted roots and
  accepted revocations, the policy engine evaluates the leaf capability plus cumulative ancestor
  budgets, and environment-signed hash-linked v2 receipts are recorded beside the v1 ledger.
- **Contracts:** [SPEC-DID.md](SPEC-DID.md), `schemas/*.v2.schema.json`, deterministic
  `tests/vectors/autheo-v2-vectors.json` checked by Python and JavaScript; HTTP API + OpenAPI and
  CLI `did` commands; web demo scenario with in-browser verification.
- v1 is unchanged: v1 schemas, vectors and JWS verification are byte-identical.

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

- No wallet, payment, THEO transfer, on-chain anchoring of ledger heads or
  delegation registries, or connection to any Autheo platform service.
- No hosted revocation service or revocation freshness guarantee (lag is bounded only
  by TTLs and distribution); no signed key-rotation records (rotation = re-delegate and revoke).
- did:web is resolved from pinned/cached documents; live HTTPS resolution is untested.
- No production key custody: issuer, service-held agent keys and local-dev DID keys are
  unencrypted local files. No HSM/KMS/wallet, no issuer rollover.
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
