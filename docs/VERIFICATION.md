# Verification record — 2026-10-12 (0.2)

## Local Linux checks (WSL2, Python 3.12.3, Node 24.19.0)

- **103 tests passed** (`python -m pytest -q`); line coverage of
  `autheo_agent_environment` **94 %** (`pytest --cov`; the lowest module is the
  legacy `webapp.py` HTTP handler at 77 %).
- `ruff check src tests review` passed.
- Contract artefacts current: `schema check schemas`, `vectors check
  tests/vectors/autheo-v1-vectors.json`, `openapi check docs/openapi.json`.
- `node interop/js/verify-vectors.mjs`: 46 JavaScript checks agree with the
  Python-generated vectors (canonical JSON, valid/invalid JWS incl. tampered
  payload, foreign key, `alg: HS256/none`, wrong `typ`/audience, expiry,
  not-yet-valid, receipt chain and tampered chain). A request signed by
  `interop/js/autheo-sign.mjs` is accepted by the Python service, and a tampered
  one is rejected (pytest).
- CLI demo + offline audit and a persistent-state CLI smoke run (init → identity →
  mandate → evaluate → ledger verify) succeeded; `serve` answered `/v1/health`,
  returned 401 without the token and `/v1/info` with it; `web` served the page.

Security behaviour covered by tests: tamper detection (edited token, forged chain
hash, deleted/reordered rows, truncation against an anchor, wrong trust anchor,
dropped triggers), revoked mandates and identities, budget exhaustion (mandate
total, windowed and lifetime policy budgets), rate limits, time windows,
escalation precedence, signature failures (foreign key, impostor kid, tampered
receipt, expired mandate), idempotency/replay conflicts, outcome reports only for
allowed decisions, API bearer/Host/Origin/body guards, non-loopback bind refusal,
and all 0.1 tests (unchanged except web-demo ledger counts, which now include the
identity and mandate lifecycle receipts).

## Not verified

- Python 3.11 and 3.13 were not run locally (CI matrix covers them on push).
- The browser UI was not exercised in a real browser (navigation to loopback was
  blocked in this environment); it is covered only by HTTP-level tests and
  `node --check`.
- The MCP bridge smoke test (`review/smoke_mcp_bridge.py`) was not rerun; the
  snapshot format it reads is unchanged.
- No run against a live JARVIS kernel or Paperclip server.
- The local venv was created with `python3 -m venv --without-pip` plus the official
  `get-pip.py` bootstrap because `ensurepip` is not installed on this host.

All operations use local data and DEMO units. No claim is made about live identity
enrollment, production policy enforcement, runtime isolation, Autheo transaction
signing, wallet balances, settlement, or real migration.

## Reproduce

```sh
python -m pip install -e '.[dev]'
python -m ruff check src tests review
python -m pytest -q
python -m autheo_agent_environment schema check schemas
python -m autheo_agent_environment vectors check tests/vectors/autheo-v1-vectors.json
python -m autheo_agent_environment openapi check docs/openapi.json
node interop/js/verify-vectors.mjs
python review/smoke_mcp_bridge.py   # requires the sibling autheo-mcp checkout with [trust]
```
