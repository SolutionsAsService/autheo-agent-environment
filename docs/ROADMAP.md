# Roadmap with verification gates

This is the concise delivery sequence. The full product scope, boundaries,
service contracts, risk register, owner questions, and phase details are in
[PRODUCT-PLAN.md](PRODUCT-PLAN.md).

## Phase 0 — reference simulation (implemented)

Signed local demo passport → scoped mandate → signed request → simulated
allow/escalate/block → integer `DEMO` budget → signed receipt → checkpoint
reference → read-only MCP snapshot.

Gate: tamper, context, expiry, replay, budget, concurrency, audit, and checkpoint
tests pass. No live identity, execution, money, runtime, or migration claim.

## Phase A — contracts and product decisions

Confirm actual Autheo identity/credential, Dev Portal, Marketplace, Layer 1,
compute runtime/attestation, privacy and operational contracts. Define the first
action class, owner, threat model, risk tiers, API schemas, degraded modes and
service owners.

Gate: responsible platform owners approve versioned contracts; unknowns remain
explicit and no endpoints or DID semantics are guessed.

## Phase B — human, organization, and agent identity

Add pluggable identity and credential adapters, distinct human/org/agent
principals, key binding and lifecycle, operator-controlled trust roots, consent,
tenant boundaries, rotation, revocation and audit. Retain the current local demo
as a separate adapter.

Gate: adversarial tests cover issuer/controller/key confusion, stale/revoked
credentials, tenant crossing, key rotation, privacy minimization and issuer
rollover. Identity alone grants no authority.

## Phase C — mandates and enforcing guardrails

Version the Agent Guardrail Interface; add request-digest-bound human approvals,
deterministic policy, atomic reservations, budgets, rate/concurrency limits,
policy rollout and revocation checks. Enforce at each consequential executor,
immediately before dispatch.

Gate: no alternate-route bypass, self-approval, delegated privilege expansion,
overspend, stale approval replay or silent allow when authority is unavailable.

## Phase D — runtime, detection, containment, and recovery

Integrate one confirmed runtime through a narrow adapter with workload
attestation, isolation, secret brokerage, short-lived credentials, correlated
monitoring, owner/on-call, kill switch, evidence preservation, rollback and
reconciliation.

Gate: fault injection and incident exercises prove safe behavior for compromised
runtime, authority outage, restart, duplicate/partial execution, stale policy,
uncertain outcome and containment without agent cooperation.

## Phase E — Hyperliquid external venue sandbox

Implement separate venue and funding adapter contracts using verified official
interfaces. Start dry-run/sandbox/testnet only; isolate signing; constrain venue,
instrument, asset, size, exposure, fee, slippage, rate and time. Reconcile order,
fill, cancel, balance, position and uncertain outcomes. Hyperliquid is external to
Autheo; trading authority does not imply transfer/funding authority.

Gate: reproducible end-to-end sandbox tests cover approval/denial, duplicate
intent, timeout, partial fill, cancellation race, outage and reconciliation. No
live funds are enabled.

## Phase F — production readiness and bounded activation

Complete independent security, custody, privacy/legal, operational, supply-chain,
penetration, monitoring, disaster-recovery and incident-response reviews. Verify
Autheo-supported test network behavior, contract finality, replay and audit
privacy. Require staged caps and separate activation approvals.

Gate: reproducible evidence, named risk owners, tested rollback, and explicit
security/product/custody approvals. Testnet success is not launch approval.

## Phase G — expand adapters and delegation

Add further compute, Marketplace, MCP, AI provider, chain and venue adapters only
with typed contracts, threat review, least privilege, lifecycle/reconciliation
tests, and an accountable owner. Consider cross-agent delegation only after core
identity, enforcement and recovery are proven; delegated scope can only narrow.

## Always-on rule

`Prevent → Control → Detect → Contain → Recover → Learn` is continuous across all
phases. Controls reduce likelihood and impact; they do not promise that every
attack is stopped or detected. A named human owner remains accountable for each
production agent and its authority.
