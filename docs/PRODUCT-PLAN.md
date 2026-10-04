# Autheo Agent Environment — product and implementation plan

**Status:** proposed product direction; not a production specification or evidence
of an integrated Autheo service. This document turns the current reference
prototype and the supplied Autheo, Agent Trust Layer, security-stack and
Hyperliquid diagrams into a reviewable delivery plan.

## 1. Product in one sentence

Give human owners and AI agents verifiable identities, narrowly delegated and
time-bounded authority, deterministic policy checks at the point of action, and
receipts that let an operator understand and respond to what happened.

Autheo should not promise a model will behave, or that every attack can be
prevented. It should make authority explicit and bounded, reject actions outside
that authority at an enforcing boundary, make suspicious activity observable,
and support containment, recovery, and learning.

**North-star sequence:**
`Identity → Authority → Budget → Assurance → Policy → Execute → Prove`

**Security operating loop:**
`Prevent → Control → Detect → Contain → Recover → Learn`

These are related, not interchangeable: the first is an action authorization
path; the second is a continuous security lifecycle. An allow decision is not an
execution result. Only the executor can report what it did, and a reconciled
receipt must distinguish proposed, authorized, submitted, executed, settled,
failed, reversed, and unknown outcomes.

## 2. What exists today

The current `0.1` code is a useful **single-host Python reference simulation**:

- Ephemeral Ed25519 demo issuer and agent keys sign local passport, mandate,
  request, receipt, and checkpoint data.
- Strict Pydantic models, short-lived tokens, exact resource/action scopes,
  local revocation, idempotency, and simulated integer `DEMO` budget checks.
- SQLite serializes simulated reservations; policy returns `allow`, `escalate`,
  or `block`. No operation is executed, including `allow`.
- Signed hash-linked local receipts and a destination-bound checkpoint reference
  demonstrate an auditable handoff shape; the handoff moves no process, secrets,
  keys, funds, or execution authority.
- The optional Autheo MCP branch exposes five read/local-inspection tools and
  one resource from a short-lived signed snapshot. It does not authorize or
  intercept other MCP operations.
- A loopback-only browser workspace lets a user submit a typed request to the
  same local simulator and inspect the decision, demo budget, and signed
  hash-linked receipt. Ephemeral keys/tokens remain server-side; session data is
  temporary. The browser surface does not create DIDs, collect human approval,
  or dispatch actions.
- Automated checks exercise the local simulator and MCP bridge; see
  `docs/VERIFICATION.md` for the recorded evidence and limits.

Not present: production human or agent DID enrollment; a consent or mandate
approval interface; an organizational identity provider integration; external
policy enforcement; a live workload runtime; credential brokerage; isolated
signing; Autheo chain/API adapters; payment execution; Hyperliquid integration;
central monitoring, revocation propagation, incident response, or recovery
services.

The current prototype's `agent_id` and `owner_id` are issuer-asserted identifiers,
not W3C DIDs or proof of a person's legal identity. Preserve the demo as a
reference implementation; do not market it as a production trust service.

## 3. Product boundaries and architecture rules

1. **Identity is not authority.** A DID/document or authenticated account says
   which subject or keys are being referenced. A separately issued, reviewable
   mandate/capability says which actions that subject may attempt, against what
   resources, under what limits and expiry.
2. **An agent cannot grant itself authority.** A named human owner and the
   organization's authorized issuer approve enrollment and mandate issuance.
   Model-generated intent can propose a request or draft a mandate, never approve
   it or widen it.
3. **Enforce at the consequence boundary.** Check fresh identity, mandate,
   revocation, policy, budgets, replay/idempotency, and approvals in the trusted
   executor immediately before dispatch/signing. A UI, MCP context, cached
   snapshot, or preflight result is not a security boundary.
4. **Keep probabilistic decisions outside deterministic permissioning.** Models
   can rank, explain, summarize, and propose. Deterministic code/policy decides
   whether the exact action is permitted; independently governed controls decide
   whether it executes.
5. **Separate control and execution.** The blockchain provides trust,
   authorization/settlement primitives, and optionally auditable commitments; it
   does not run application workloads. Marketplace schedules; compute mesh runs
   workloads; the developer platform exposes workflows. Agent Environment
   coordinates policies and adapters, not all of Autheo.
6. **Least disclosure by default.** Keep personal identity attributes, prompts,
   credentials, trading intent, and action payloads off-chain. Where supported
   and justified, anchor a privacy-reviewed digest/receipt reference only.
7. **Fail safely, but preserve availability intentionally.** High-impact
   actions fail closed when authority cannot be checked; read-only and
   non-consequential operations may have separately documented degraded modes.
   Never quietly convert an unavailable guardrail into an allow.
8. **No security guarantee.** Controls reduce likelihood and impact; none
   guarantee immunity from attack, model correctness, complete detection, or
   successful recovery.

## 4. Identity and authority model

Support human, organization/workload-owner, and agent subjects as distinct
principals. The design should be DID-compatible, while avoiding a premature
choice of DID method or Autheo identifier until the platform's documented
identity contract is available.

### Human and organization identities

- Authenticate the human through the selected organizational IdP; use a
  reviewed step-up ceremony for high-risk enrollment, mandate changes, and
  approvals.
- Resolve organization membership, role, and authority from an authoritative
  source. A DID by itself does not prove a legal identity, employment, ownership,
  or that an approval is informed.
- Link human and organization identifiers only with explicit purpose, issuer,
  expiry, and revocation semantics. Minimize PII disclosed to agents and public
  ledgers.

### Agent identities

- Give each agent/workload an independently revocable identifier and
  cryptographic key binding. Record controller/owner, issuer, environment,
  runtime/workload attestation reference, model/application provenance where
  useful, creation time, key rotation state, and revocation status.
- Keep key proof distinct from provenance: possession of a key proves control of
  that key, not that a model or binary is safe or unchanged.
- Define lifecycle states: proposed → verified → active → suspended/revoked →
  retired. Re-enrollment must not silently inherit old authority.
- Support non-human workload identity and short-lived credentials; never place
  issuer, user, wallet, or agent signing secrets in browser code or agent prompt
  context.

### Mandates / Agent Guardrail Interface

Issue an immutable, versioned authority object (and implementation-compatible
credential/capability representation) with at least:

- subject agent ID and accountable human/organization owner;
- issuer, audience, tenant, environment, policy version, issue/expiry time,
  session and revocation reference;
- exact tools/functions, resource and asset/network scopes; explicit deny rules;
- per-action and aggregate budgets, limits/currency units, rate/concurrency
  quotas, and reservation/commit/release semantics;
- destination/recipient constraints when applicable;
- approval thresholds, eligible approver roles, request digest, decision reason,
  and approval expiry;
- required assurance signals, monitoring, evidence retention class, and receipt
  requirements;
- emergency stop and revocation behavior, with the allowed cache/freshness
  window explicit.

Delegation may only attenuate scope, duration, and budget. No DID document or
identity credential alone grants a tool call, contract method, payment, or
resource entitlement. Mandate and signature formats remain an adapter seam until
Autheo identity standards are verified.

## 5. Mapping the Autheo ecosystem

| Autheo area | Role in the agentic trust product | Boundary / integration question |
| --- | --- | --- |
| Organization | Governance, policy ownership, issuer/operator accountability, human owner registry | Which organization roles may enroll agents, issue mandates, approve, revoke, and view evidence? |
| Layer 1 | Verifiable identities/claims, programmable agreements, settlement, governance, optional minimal audit anchoring | What identity/credential, contract, network, finality, revocation, and privacy APIs are actually supported? |
| Marketplace | Resource discovery, task intake, pricing/SLA/policy context, scheduling request | Which marketplace API supplies the canonical task/resource IDs and accepts authorization results? |
| Distributed Compute Mesh | Isolated workload execution across nodes, runtime attestation, resource metering | What attestation, isolation, secrets, termination, metering, and rollback controls exist per node? |
| Developer Platform | CLI/SDK/API, integration templates, operations and evidence views | Which API and authentication contract is supported; what events can be correlated end-to-end? |
| Agent Environment (this repo) | Identity/mandate adapters, deterministic guardrail orchestration, approvals, execution adapters, evidence correlation | It is a proposed integration/control layer, not a replacement for the five platform areas. |

**Layer naming is an open contract question:** the supplied platform-stack
reference labels the trust platform “Layer 1,” while the Hyperliquid flow calls
the Autheo mesh/orchestration boundary “L0.” This plan uses “Autheo platform” or
“Layer 1” only when referring to the supplied five-area stack; confirm canonical
product terminology and boundaries with platform owners before encoding names in
APIs or contracts.

## 6. Hyperliquid as an adapter example

Hyperliquid demonstrates the architecture; it is an **external execution and
settlement venue**, not an Autheo component. The safe reference flow is:

1. A human, application, or agent proposes a typed intent through a documented
   Marketplace/API/MCP entry point.
2. The control plane resolves the human/organization and agent identities,
   ownership, key state, environment and fresh mandate.
3. Assurance gathers relevant market/account data through read-scoped venue
   adapters, validates freshness/schema, and labels external data as untrusted
   input (not policy).
4. A deterministic route planner produces a bounded plan. Policy checks allowed
   venue/instrument, size, exposure, per-order and cumulative budget, slippage,
   rate, session/time, and human-approval thresholds.
5. If permitted, a separately governed signing service authorizes an exact
   payload under venue/network/asset limits. The agent never receives private
   wallet or venue secrets. In the proposed initial integration, use venue
   sandbox/testnet or dry-run only.
6. The adapter submits with an idempotency/correlation ID, then reconciles
   acknowledgements, fills, balances, positions, fees, cancellations, and
   uncertain/partial outcomes. Route deposits/withdrawals through a distinct
   funding policy and signer; do not infer funding approval from trading
   permission. HyperEVM contract flows, if ever supported, are a separate adapter.
7. Return a signed, provenance-linked receipt with requested, authorized,
   submitted, executed, settled, failed, reversed, or unknown state. Anchor only
   a privacy-reviewed commitment if the actual Autheo contract supports it.

No implementation may guess Hyperliquid/Autheo endpoints, signing semantics,
supported test environments, or finality. Confirm current official interfaces and
terms, then test against sandbox fixtures before enabling any live key or funds.

## 7. Defense-in-depth operating model

| Layer | Example controls and evidence |
| --- | --- |
| Prevent | Verified owner/workload identities; least privilege; secrets broker; scoped credentials; supply-chain provenance; input and data-source validation |
| Control | Approved model/tool/runtime registry; typed schemas; prompt-injection-aware untrusted-data handling; deterministic policy; budgets; high-risk human approval |
| Detect | Input/output/tool validation; signed decision/execution events; runtime and tool telemetry; behavior drift, rate/exposure anomaly, integrity and threat signals |
| Contain | Immediate agent/session/credential revocation; venue order cancel/pause where supported; network/tool isolation; operator kill switch; bounded blast radius |
| Recover | Known-good runtime/config restore; reconcile uncertain transactions; safe rollback/compensation; evidence preservation; controlled re-enable with fresh mandate |
| Learn | Incident review; policy/model/tool allowlist updates; tests for the incident path; owner acceptance; auditable change and revalidation |

Every production agent needs a named accountable human owner, an on-call/escalation
route, and explicit operational limits. Detection can be late or incomplete;
containment and recovery need to work independently of model cooperation.

## 8. Delivery plan and exit criteria

The phases are ordered gates, not promises of delivery dates. Each phase produces
a deployable, reviewable increment. Keep demo mode available and visibly distinct
from production status.

### Phase A — contracts and product decisions

- Confirm Autheo identity/credential primitives, DID compatibility and supported
  methods, issuer authority, Dev Portal auth/API, Layer 1 contract/network/finality,
  Marketplace request API, compute runtime/attestation, audit requirements, and
  legal/privacy boundaries with platform owners.
- Select initial user journey and operation class; define exact threat model,
  risk tiers, owners/approvers, data classification, SLO and degraded modes.
- Publish versioned interface schemas for identity, mandate, decision, approval,
  action intent, status event, and receipt. Record unsupported assumptions.

**Exit gate:** API/identity owners sign off on versioned contracts; ambiguity is
tracked rather than filled with fabricated endpoints or chain behavior.

### Phase B — identity foundation (read-only/inert)

- Add pluggable `IdentityProvider` and `CredentialResolver` interfaces; preserve
  current local demo as one explicit adapter.
- Model human owner, organization, and agent DIDs/subjects separately from key
  material, issuer claims, runtime provenance, and mandate.
- Add enrollment/rotation/revocation state machine, audit records, tenant
  boundaries, and operator-controlled trust roots. Begin with test identities.
- Prototype a credential format only after verifying Autheo requirements;
  evaluate maintained W3C DID/VC-compatible tooling rather than custom crypto.

**Exit gate:** negative tests cover forged/untrusted DID methods, wrong controller,
key rotation, revoked/expired credentials, tenant confusion, stale resolution,
issuer rollover and privacy minimization; no execution adapter is enabled.

### Phase C — mandate and deterministic guardrail service

- Version the Guardrail Interface and policy input/output; distinguish
  authorization decision from reservation and from execution result.
- Add immutable approval requests bound to one payload digest, named approver,
  expiry and policy version. Agents cannot approve or mutate pending requests.
- Implement atomic per-action/cumulative budgets, rate/concurrency controls,
  policy rollout/rollback, revocation freshness, replay protection and
  idempotency across service restarts/replicas.
- Place enforcement middleware at every consequential API/tool boundary;
  demonstrate that alternate routes cannot bypass it.

**Exit gate:** adversarial tests prove fail-closed enforcement, non-escalating
delegation, no stale approval/policy replay, no overspend under concurrency, and
recoverable reservation behavior on timeout/partial failure.

### Phase D — monitored runtime and operational response

- Integrate one actual Autheo/selected workload runtime via a narrow adapter;
  use isolated workloads, attestation/provenance, short-lived credentials and
  separate secret brokerage.
- Emit correlated decision, dispatch, runtime, and outcome events to a monitored
  audit path; define data minimization and retention before collecting prompts.
- Implement human-owned kill switch, session and credential revocation, workload
  isolation, incident evidence capture, rollback/reconciliation runbooks, and
  independent recovery tests.

**Exit gate:** tabletop and fault-injection exercises demonstrate containment and
recovery without agent cooperation; stale policy, unreachable authority, unknown
execution result, compromised runtime, duplicate/reordered events and restart
conditions have explicit safe behavior.

### Phase E — Hyperliquid sandbox/testnet venue adapter

- Build venue-neutral `ExecutionVenue` and separate `FundingVenue` contracts;
  keep planning, trust policy, signing and venue transport independently testable.
- Implement official current sandbox/testnet interfaces only after owners verify
  endpoint, key, signature, order, cancellation and reconciliation semantics.
- Use dry-run by default; enforce instruments/assets, price/slippage/exposure,
  order size, fees, rate, time and per-session/cumulative budget. Separate
  trading, transfers, deposits/withdrawals and contract interaction authority.
- Introduce a dedicated signer boundary, never agent-held venue secrets; execute
  only exact human-reviewed payloads when thresholds require it.
- Reconcile order lifecycle, fills, fees, position/balance changes and uncertain
  acknowledgements into receipts; retain venue evidence references.

**Exit gate:** no live funds; simulated/sandbox end-to-end tests cover denial,
approval, timeout, retry, partial fill, cancel race, duplicate intent, reconciliation
and venue outage. Independent operator can explain each state and stop the adapter.

### Phase F — production readiness and bounded activation

- Complete independent threat-model review, penetration testing, key/custody
  review, privacy/legal sign-off, disaster recovery, incident runbooks, monitoring
  SLOs, support ownership, and supply-chain review.
- Validate on Autheo-supported test network first; prove contract authorization,
  finality/reorg behavior, transaction replay/caps, audit privacy, and rollback.
- Require separately authorized, staged activation per tenant/operation with
  low caps, manual oversight, easy revocation and a documented rollback path.

**Exit gate:** named security/product/operations owners accept residual risks;
test evidence is reproducible; live activation requires explicit executive,
security, and custody approvals. A successful testnet run is not a launch approval.

### Phase G — expansion

Add further compute, Marketplace, MCP, AI provider, chain and venue adapters; then
consider constrained agent-to-agent delegation. Every new adapter gets a threat
model, typed contract, least-privilege capabilities, lifecycle/reconciliation
tests, and an owner. Delegation only attenuates authority and remains traceable to
the original accountable human/organization.

## 9. Proposed service seams

Keep product modules small and replaceable; do not couple UI/MCP code directly to
Autheo or Hyperliquid specifics:

- `IdentityProvider` / `CredentialResolver` — subjects, controllers, key status,
  issuer trust and revocation.
- `MandateIssuer` / `MandateStore` — immutable authority, versioning, approval,
  expiration and revocation.
- `PolicyDecisionPoint` — deterministic decision plus reason, policy digest and
  obligations; no side effect.
- `BudgetLedger` — atomic reservations and commit/release/reconcile by canonical
  operation ID.
- `ApprovalService` — signed, expiring human decision for one exact payload.
- `ExecutionAdapter` — reauthorize immediately before dispatch, idempotent
  submit, report state; implementations for compute, Marketplace, chain, or venue.
- `CredentialBroker` / `Signer` — isolated service identities and key custody;
  never callable as arbitrary signing oracle.
- `EvidenceRecorder` / `Verifier` — correlate identity, mandate, policy, approval,
  executor evidence and final status; optionally export minimized commitments.
- `ResponseController` — revoke, pause, isolate, cancel where supported, preserve
  evidence and reconcile recovery.

MCP remains a discovery/context/transport adapter. It can surface typed intent
and status, but should not bypass the same trusted authorization and executor
boundaries used by APIs and the Marketplace.

## 10. Core data records and lifecycle

At minimum define versioned records for `Principal`, `KeyBinding`, `AgentProfile`,
`Mandate`, `ActionIntent`, `PolicyDecision`, `Approval`, `BudgetReservation`,
`ExecutionAttempt`, `StatusEvent`, `EvidenceReference`, `Receipt`, `Revocation`,
and `Incident`. Each record must carry stable IDs, schema/version, issuer or
producer, tenant/environment, timestamps, correlation/idempotency IDs, and
privacy classification as applicable.

The lifecycle should be queryable without flattening distinct facts:

`proposed → authenticated → authorized | denied | needs_approval → reserved →
submitted → executing → executed | failed | unknown → reconciled → settled |
reversed`

An authorization receipt cannot claim execution. `unknown` is a first-class
state: reconcile before retrying an action that might already have occurred.

## 11. Non-goals and risk register

### Initial non-goals

- Guaranteeing that every attack, prompt injection, hallucination or malicious
  action will be prevented or detected.
- Treating model output, a DID, an MCP snapshot, a green UI indicator, or an
  on-chain hash as sufficient authorization or proof of execution.
- Moving user/agent keys, prompts, private identity claims or full transaction
  payloads onto a public chain.
- Shipping a general-purpose wallet, autonomous unrestricted trader, broad shell
  executor, model training pipeline, or auto-migration engine in the initial MVP.
- Claiming Hyperliquid, Autheo Layer 1, a production DID method, or the compute
  mesh is integrated before its live contracts are verified.

### Principal risks and treatment

| Risk | Treatment / unresolved owner decision |
| --- | --- |
| DID/controller mistaken for legal ownership or consent | Require authoritative issuer/IdP, verified owner flow and explicit consent evidence; define who can attest |
| Prompt injection or poisoned external data changes an agent proposal | Treat retrieved content as untrusted; validate schemas/data provenance; policy evaluates the exact bounded action, not rationale text |
| Confused deputy or cross-tenant capability reuse | Bind issuer, subject, audience, tenant, resource, environment and policy version; test cross-boundary replay |
| TOCTOU, stale revocation or policy cache | Recheck at executor; define measurable freshness and fail-closed behavior for consequential actions |
| Key theft or compromised signing service | Separate issuer/agent/venue signers, HSM/KMS where appropriate, narrow signing API, rotation, monitoring and independent stop control |
| Double spend / duplicate or uncertain venue actions | Atomic budget reservations, idempotency, state reconciliation, unknown state; never blind retry |
| On-chain privacy leakage or misleading immutability claim | Minimize and review anchored data; publish only digest/necessary proof; explain chain finality, forks and key trust assumptions |
| Incomplete monitoring or unsafe recovery | Name human owner/on-call, test kill switch and rollback, preserve evidence, rehearse incident workflow |
| Platform APIs or DID support differ from assumptions | Phase A owner sign-off; versioned adapters; no guessed endpoint/contract behavior |

## 12. Decisions required from Autheo owners

Before Phase B implementation, obtain answers for:

1. What identity system, DID method(s), controller/owner semantics, credential
   formats, resolver, key recovery and revocation services does Autheo support?
2. Which human/organization roles may issue, approve, delegate, revoke, and
   override mandates, and what consent evidence must be retained?
3. What are the supported Layer 0/Layer 1 APIs, contract interfaces, chain IDs,
   environments, transaction finality, fees, reorg/rollback rules, and audit
   anchoring interface?
4. What Marketplace/Dev Portal APIs and auth audiences exist? Which service owns
   canonical tenant, task, resource, billing and idempotency identifiers?
5. What runtime/mesh isolation and attestation are deployed; how do secret
   brokerage, metering, termination, evidence export, and recovery work?
6. Which initial action is in scope, who owns it, what data can leave the tenant,
   which risks require human approval, and who is on call?
7. For a Hyperliquid adapter, which official environment and current interfaces
   are approved, who owns venue credentials/custody, and what exposure/funding
   caps are acceptable?

Until answered, keep integration points abstract and demos inert. The next
engineering deliverable should be the Phase A contract pack and threat-model
review—not a speculative DID or trading implementation.

## 13. Companion material

- [North-star architecture diagram](AUTHEO-AGENT-TRUST-ARCHITECTURE.svg)
- [Current implementation and claim ceiling](IMPLEMENTATION-STATUS.md)
- [Threat model and honest limits](THREAT-MODEL.md)
- [Roadmap and verification gates](ROADMAP.md)
- [Dev Portal / Layer 0 integration notes](DEV-PORTAL-LAYER0.md)
- [Existing solutions preflight](EXISTING-SOLUTIONS.md)
