# Declarative policy (`autheo.policy/v1`)

A policy is **operator configuration** loaded from the state directory
(`policy.yaml`, YAML or JSON). It is never agent input and it can only **narrow**
what a signed mandate already grants. Evaluation is deterministic: a pure
function of the policy, mandate, request, revocation state, prior receipts for
the same mandate and the clock. Schema: `schemas/policy.v1.schema.json`.

## Evaluation order and outcome

All checks run (so explanations are complete); the outcome is
**block > escalate > allow**.

1. **Mandate checks (0.1-compatible, fixed order):** `revoked`, `scope_denied`,
   `resource_denied`, `per_action_limit`, `total_budget_limit`, then tool checks:
   `tool_required` (`tool.invoke` without a tool) and `tool_denied` (a named tool
   that is not in the mandate's exact `tools` list — a mandate never grants a
   tool implicitly).
2. **Policy lists:** `scopes`, `tools`, `resources` each have glob `allow`/`deny`
   lists (`fnmatch`, case-sensitive). Deny wins; a non-empty allow list must
   match. Failure reasons: `policy_scope_denied`, `policy_tool_denied`,
   `policy_resource_denied`.
3. **Budgets:** `budgets: [{id, limit_minor, window_seconds?, actions?, tools?}]`.
   Sums prior **allowed** simulated amounts in the window (or the mandate's whole
   history when `window_seconds` is omitted) → `budget_exhausted:<id>`.
4. **Rate limits:** `rate_limits: [{id, max_requests, window_seconds, actions?, tools?}]`.
   Counts prior allow+escalate decisions in the window → `rate_limited:<id>`.
5. **Time windows:** `time_windows: [{id, start, end, days?, timezone?, outside: block|escalate}]`.
   `HH:MM`, half-open `[start, end)`; overnight windows (`22:00`-`06:00`) belong
   to the start day. Each applicable window must contain "now" →
   `outside_time_window:<id>` (blocks or escalates).
6. **Escalation:** the mandate's `approval_threshold_minor`
   (→ `human_review_required`, disable with `use_mandate_approval_threshold: false`)
   and `escalations: [{id, amount_minor_gt?, actions?, tools?, resources?}]`
   (all given conditions must match) → `policy_escalation:<id>`.

Allowed requests get the reason `within_demo_policy`. With the built-in
`policy:mandate-only` policy, outcomes and reasons are identical to 0.1.

`escalate` means "requires human review". This prototype has **no approval
workflow**: nothing turns an escalation into an allow. Integrations (JARVIS,
Paperclip approvals) must run their own approval and then request a fresh,
explicitly granted mandate or decision; see INTEGRATIONS.md.

## Explanations

Each decision carries `explanation: [{check, outcome, detail}]` with outcome
`pass | fail | escalate | not_applicable`, e.g.

```json
{"check": "policy.budget:hourly", "outcome": "fail", "detail": "25 + 10 exceeds 30 (last 3600s)"}
```

The decision also includes `policy_id`, `policy_digest` (canonical-JSON SHA-256
of the policy) and `request_digest`; receipts record `policy_id`/`policy_digest`
so an auditor can tell which policy produced each outcome.

## Example

```yaml
schema_version: autheo.policy/v1
policy_id: policy:jarvis-workstation
description: JARVIS kernel tools on the local workstation
tools:
  allow: ["git.*", "fs.read", "browser.open", "deploy.*"]
  deny: ["shell.*", "fs.delete"]
resources:
  deny: ["repo:secrets-*"]
budgets:
  - id: hourly-model-spend
    limit_minor: 500
    window_seconds: 3600
    actions: ["model.invoke"]
rate_limits:
  - id: burst
    max_requests: 60
    window_seconds: 60
time_windows:
  - id: office-hours-writes
    start: "08:00"
    end: "19:00"
    days: [mon, tue, wed, thu, fri]
    timezone: America/Denver
    outside: escalate
    actions: ["file.write", "message.send"]
escalations:
  - id: deploys
    tools: ["deploy.*"]
use_mandate_approval_threshold: true
```

Validate with `python -m autheo_agent_environment policy validate policy.yaml`.
A policy change takes effect when the CLI/API process next loads it (restart
`serve`); there is no hot reload, rollout or rollback machinery yet.
