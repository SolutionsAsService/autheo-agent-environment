# Verification record — 2026-09-29

## Local Linux checks

- Agent Environment: **28 tests passed**.
- MCP prototype branch: **86 tests passed**, Ruff and mypy passed.
- Full MCP stdio protocol: **44 tools / 5 resources** successfully exercised
  against local contract fixtures through both module and console entrypoints.
- Configured trust bridge: all five trust tools plus the resource checked through
  both entrypoints; real environment-produced signature accepted, invalid receipt
  limit rejected, tampered snapshot returned `invalid_snapshot`.
- Security behavior covered: wrong key/issuer/subject/audience/type, expiry/future
  validity, overlong validity, schema/amount rejection, revocation, idempotency,
  concurrency, cumulative limits, narrowed handoff scope, replay, audit tampering,
  and missing audit tails relative to a separately supplied head.

All functional operations use local data and DEMO units. No claim is made about
live identity enrollment, production policy enforcement, runtime isolation,
Autheo transaction signing, wallet balances, settlement, or real migration.

## Reproduce

```sh
python -m pytest tests -q
python -m ruff check src tests review
python review/smoke_mcp_bridge.py
```

The last command requires the sibling MCP prototype installed in the same test
venv with its `trust` dependencies. Backend fixture smoke commands are documented
in that project's `docs/AGENT-TRUST.md`.
