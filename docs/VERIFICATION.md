# Verification record — 2026-10-12 (0.3)

## Local Linux checks (WSL2, Python 3.12.3, Node 24.19.0)

- **235 tests passed** (`python -m pytest -q`): the 103 tests of 0.2 unchanged plus 132 new v2
  tests. Line coverage of `autheo_agent_environment` **94 %** (`pytest --cov`); new v2 modules:
  `cli_did` 99 %, `models_v2` 97 %, `data_integrity` 97 %, `jcs` 96 %, `didenv` 95 %,
  `delegation` 94 %, `did` 93 % (uncovered: the real HTTPS fetch path, never run),
  `verifier` 88 %.
- `ruff check src tests review` passed.
- Contract artefacts current: `schema check schemas` (v1 files byte-identical, v2 files added),
  `vectors check tests/vectors/autheo-v1-vectors.json` (unchanged),
  `vectors-v2 check tests/vectors/autheo-v2-vectors.json`, `openapi check docs/openapi.json`.
- `node interop/js/verify-vectors.mjs`: 46 v1 checks agree (unchanged).
- `node interop/js/verify-v2-vectors.mjs`: **179 v2 checks agree** with the Python-generated
  vectors: base58, varint, JCS (incl. RFC 8785 examples and rejections), did:key encode/decode
  (W3C and did:key-spec keys, invalid codecs/lengths), did:web URLs, the W3C eddsa-jcs-2022
  example (canonical forms, hash data, proofValue byte-for-byte), 22 chain cases, 5 invocation
  cases, 8 bundle cases, ledger and tampered ledger.
- An invocation signed in JavaScript (`sign-v2-invocation.mjs`, WebCrypto) is **byte-identical**
  (same JCS bytes, same Ed25519 signature) to the Python-signed one and verifies in Python.
- The CI v2 smoke script (create three DIDs, delegate twice, invoke, verify the chain offline,
  trust root, evaluate, verify the bundle offline with `autheo-verify`, revoke, confirm the
  revoked chain fails, verify the v2 ledger) passed locally.

### What the v2 tests cover

- **Spec vectors:** draft-msporny-base58 vectors; unsigned-varint/multicodec prefixes; the W3C
  Data Integrity EdDSA example key pair -> did:key; the did:key spec's Ed25519->X25519
  `keyAgreement` example; did:web method-spec URL examples; RFC 8785 sorting and string examples;
  the W3C eddsa-jcs-2022 example reproduced byte-for-byte.
- **Property tests (hypothesis):** base58 and did:key round trips for random inputs/seeds; JCS
  output is valid JSON and idempotent; pattern-cover soundness (a covered child pattern never
  matches a value its parents do not); issuer refusal and verifier `attenuation_violation` agree
  exactly with the attenuation rules for random parent/child capabilities; monotonicity (any
  request a child capability permits, its parent permits).
- **Chain verification:** 2- and 3-link chains; untrusted root; tampering with any link;
  replaced parent; wrong parent digest; issuer that is not the parent's subject; proof by a key
  other than the issuer; wrong proof purpose; depth limits; widened validity; per-link expiry,
  not-yet-valid and the 2 s skew boundary; length/shape limits.
- **Revocation:** effective from `revoked_at`; entitled signers (issuer, ancestors, subject) vs
  ignored strangers; parent revocation invalidates descendants; binding to the exact credential;
  tampered records ignored; replay/conflict of records in the ledger.
- **Invocations:** expiry, not-yet-valid, tampering, malformed, invoker that is not the leaf.
- **Decision point and ledger:** allow/escalate/block with explanations, cumulative ancestor
  budgets shared by sibling sub-agents, authentic-but-unauthorised chains recorded as blocks
  (untrusted root, revoked), forged chains/invocations rejected and not recorded, idempotent
  replay and conflicting reuse, SQLite edits detected, append-only triggers, v1 ledger still
  verifies, ledger export verification (reorder, truncation vs anchor, foreign issuer, edits).
- **Bundles (offline):** allow/block verified; wrong environment DID; edited receipt; swapped
  invocation; wrong root; a revocation predating the decision makes an `allow` unsupported.
- **Surfaces:** every new HTTP route (incl. error mapping), CLI offline and state-backed
  commands (incl. key files created 0600 and never overwritten), identities exposing the agent
  key's DID, the demo server running the DID scenario, the served browser verifier being
  byte-identical to `interop/js/autheo-did.mjs`.

## Not verified

- Python 3.11 and 3.13 were not run locally (the CI matrix runs them on push).
- **did:web was never resolved against a live server**; only cached/pinned documents and a
  mocked fetcher are tested.
- The browser UI (including in-browser WebCrypto verification in `did-demo.js`) was not
  exercised in a real browser - navigation to loopback is blocked by policy in this
  environment. The same `autheo-did.mjs` is exercised in Node via WebCrypto, the scenario's API
  calls are tested over HTTP, and `did-demo.js` passes `node --check`.
- No interoperability run with third-party VC/Data Integrity libraries; conformance rests on
  reproducing the W3C example and on the published vectors.
- The MCP bridge smoke test (`review/smoke_mcp_bridge.py`) was not rerun; no run against a live
  JARVIS kernel or Paperclip server.
- The local venv was created with `python3 -m venv --without-pip` plus `get-pip.py` because
  `ensurepip` is not installed on this host.

All operations use local data and DEMO units. No claim is made about live identity enrollment,
production key custody, revocation freshness, on-chain anchoring, runtime isolation, wallets,
settlement, or real migration.

## Reproduce

```sh
python -m pip install -e '.[dev]'
python -m ruff check src tests review
python -m pytest -q --cov=autheo_agent_environment
python -m autheo_agent_environment schema check schemas
python -m autheo_agent_environment vectors check tests/vectors/autheo-v1-vectors.json
python -m autheo_agent_environment vectors-v2 check tests/vectors/autheo-v2-vectors.json
python -m autheo_agent_environment openapi check docs/openapi.json
node interop/js/verify-vectors.mjs
node interop/js/verify-v2-vectors.mjs
python review/smoke_mcp_bridge.py   # requires the sibling autheo-mcp checkout with [trust]
```
