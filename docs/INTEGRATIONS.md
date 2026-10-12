# Integrating with JARVIS and Paperclip

**Status:** design notes plus tested reference code in this repository. No code
was changed in the JARVIS or Paperclip repositories, and no end-to-end run
against a live JARVIS kernel or Paperclip server has been performed. What *is*
tested here: the HTTP API, the CLI, a request signed by the dependency-free
JavaScript signer (`interop/js/autheo-sign.mjs`) being accepted by the Python
service, and the JavaScript verifier agreeing with the committed vectors.

The trust layer is a **policy decision point and evidence ledger**. The
integrating runtime is the **policy enforcement point**: it must call Autheo
immediately before a consequential effect, dispatch only on `allow`, and record
what it did. Autheo never executes anything and never holds funds. Since 0.3 agents and
principals can be did:key identities whose authority comes from signed delegation chains
(see "Adopting v2" below); nothing needs to be registered with Autheo.

## Common pattern

1. **Run the service locally.** `python -m autheo_agent_environment init` then
   `serve` on loopback. Give the runtime the URL and the bearer token as a secret
   reference (never in prompts or frontend code). Pin the trust anchor from
   `GET /v1/info` (public key + `kid`) out of band; verify receipts against the
   pinned key, not against whatever a response says.
2. **Enroll agents with agent-held keys.** The runtime generates an Ed25519 key
   per agent/workload and enrolls only the public key (`POST /v1/identities`).
3. **Grant mandates from a human/operator path,** never from model output:
   `mandate grant` (CLI) or `POST /v1/mandates` called by an operator-authorised
   control path. Mandates are short-lived (≤ 1 h) — renew deliberately.
4. **Before each consequential effect:** sign an `autheo-request+jwt` with the
   agent key and `POST /v1/evaluate`.
   * `allow` → dispatch now (do not cache the decision);
   * `escalate` → do **not** dispatch; open a human approval in the runtime;
     after approval, an operator grants a new narrowly-scoped mandate and the
     runtime re-evaluates a fresh request;
   * `block` → fail the step with the returned reason codes/explanation;
   * API unreachable, 4xx/5xx or verification failure → **fail closed** for
     consequential actions.
5. **After the effect:** `POST /v1/receipts/outcome` with an agent-signed
   `autheo-outcome+jwt` (`status` + `detail_sha256` of the tool result). Store
   `receipt_token` values in the runtime's own event log.
6. **Audit:** periodically `GET /v1/ledger/verify` and store `ledger anchor` heads
   in a system the Autheo host cannot rewrite (e.g. the runtime's database or a
   git repo); verify offline with `interop/js/autheo-verify.mjs`.

## JARVIS (Node 24 kernel)

The JARVIS Phase 1a kernel (`kernel/`) already has scoped Bearer-authenticated
loopback HTTP, SQLite tasks/events, independently authored work-approval
receipts and integer admission budgets (`kernel/governance.js`), and a contract
rule to "recheck current policy ... immediately before effects"
(`docs/CONTRACTS.md`). Proposed mapping:

| JARVIS concept | Autheo |
| --- | --- |
| actor / workspace capability | agent passport + mandate (scopes, resources, tools) |
| `authorize(actor, capability)` before effects | `POST /v1/evaluate` with a kernel-signed request; dispatch only on `allow` |
| `reserveBudget` admission units | mandate `per_action_minor`/`total_budget_minor` + policy `budgets` (DEMO units, not money) |
| approval receipts (`approvalReceiptRefs`) | escalate → JARVIS approval → new mandate; store Autheo receipt tokens alongside |
| MCP tool identity (`serverId+pin+toolName+schemaHash`) | `tool` name in the request; put the pinned identity in the tool id (e.g. `mcp:fixture:text.digest`) and allow-list it in the mandate |
| task events / receipts | `receipt_token` + `chain_hash` appended to the task's event stream |
| JCP manifest hash, task handoff | `checkpoint.artifact_sha256`; `POST /v1/checkpoints` → `/v1/handoffs/accept` |

Kernel-side sketch (uses only `node:crypto`):

```js
import { generateKeyPairSync } from 'node:crypto';
import { signRequest, signOutcome, keyFingerprint } from './interop/js/autheo-sign.mjs';
import { verifyJws } from './interop/js/autheo-verify.mjs';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');   // keep privateKey in the kernel
// enroll once: POST /v1/identities {agent_id, owner_id, environments, public_key: publicKey.export({type:'spki',format:'pem'})}

async function guardedEffect({ mandateId, tool, resource, run }) {
  const requestId = `jarvis:${crypto.randomUUID()}`;
  const body = { schema_version: 'autheo.request/v1', request_id: requestId, agent_id: AGENT,
    environment: 'env:research', mandate_id: mandateId, action: 'tool.invoke', resource, tool,
    amount_minor: 0, asset: 'DEMO' };
  const res = await fetch(`${AUTHEO_URL}/v1/evaluate`, { method: 'POST',
    headers: { authorization: `Bearer ${AUTHEO_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({ request_token: signRequest({ privateKey, agentId: AGENT, environment: 'env:research', body }) }) });
  if (!res.ok) throw new Error('autheo_unavailable');            // fail closed
  const verdict = await res.json();
  if (verdict.outcome !== 'allow') return { status: verdict.outcome, reasons: verdict.reasons };
  const result = await run();                                     // the kernel performs the effect
  // then POST /v1/receipts/outcome with signOutcome(...) and store verdict.receipt_token
  return { status: 'done', result, receipt: verdict.receipt_token };
}
```

Gaps before this is real: the kernel needs a key store for agent keys, a
SecretRef for the API token, a decision on which effects are "consequential",
and tests in the JARVIS repo. JARVIS's own approval/budget code stays
authoritative for its domain; Autheo adds signed, verifiable evidence and a
second deterministic gate.

## Paperclip

Paperclip already gives each agent a persistent Ed25519 keypair (SPKI PEM;
`keyId = "sha256:" + base64url(SHA-256(SPKI DER))` — **the same construction
Autheo uses as the agent `kid`**), exposes the public/private PEM to managed runs
as `PAPERCLIP_AGENT_PUBLIC_KEY` / `PAPERCLIP_AGENT_PRIVATE_KEY`, and has board
approvals and monthly budgets with hard stops (see Paperclip `doc/AGENT-IDENTITY.md`,
`docs/api/approvals.md`, `doc/SPEC-implementation.md`).

| Paperclip concept | Autheo |
| --- | --- |
| agent identity key | passport with `public_key = PAPERCLIP_AGENT_PUBLIC_KEY` (custody `agent_held`); requests signed in the managed run |
| company / board member | `owner_id` (issuer assertion only — not a verified legal identity) |
| `budgetMonthlyCents`, hard-stop | policy `budgets` with a rolling `window_seconds` (Autheo has **no calendar-month window**; amounts are DEMO units, not cents) |
| approval (`request_board_approval`, approve/reject) | Autheo `escalate` → create a Paperclip approval; on approve, an operator grants a one-off mandate (exact resource, `total_budget_minor` = approved amount) and the run re-evaluates |
| run results / activity | outcome receipts signed with the agent key; receipt tokens attached to the issue/run activity |

Approval never converts a past `escalate` receipt into an allow; it produces a
new mandate and a new decision, both on the ledger.

## Honest limits for both

* Local, single-host reference: SQLite on one machine; file-based issuer key.
* No TLS; loopback only by default. No multi-tenant isolation in the API.
* Decisions are only as good as the integrating runtime's enforcement: Autheo
  cannot stop a runtime that skips the check.
* Outcome receipts are claims by the executor, not proof of what happened.
* No wallet, payment, chain anchoring or Autheo platform service is involved. v2 DIDs and
  delegation VCs are local cryptographic objects, not registrations anywhere.

## Adopting v2 (notes only - JARVIS and Paperclip were not modified)

v1 keeps working unchanged: JARVIS (commit f8006b7) vendors the v1 schemas and vectors and
verifies v1 receipts in JS; none of that changes. v2 is additive and can be adopted per flow.

**What to vendor:** `interop/js/autheo-did.mjs` (single dependency-free file, WebCrypto),
`schemas/*.v2.schema.json` and `tests/vectors/autheo-v2-vectors.json`, plus a CI step running
`verify-v2-vectors.mjs` against the vendored vectors (the same pattern as v1).

**JARVIS (Node 24 kernel)**

1. Each kernel agent/workload generates an Ed25519 key and uses its did:key as its identity
   (`didFromSeed` / any WebCrypto Ed25519 key); the human operator's root did:key (kept outside
   the kernel, ideally hardware-backed) is pinned in the Autheo environment (`did trust`) and in
   JARVIS config.
2. Work approval becomes delegation: when a human approves a task, the operator path issues an
   `AutheoDelegation` from the root DID to the agent DID with the task's scopes/resources/budget
   and a short `validUntil`. Agents that spawn helpers sub-delegate narrower credentials
   themselves - no Autheo call needed.
3. Before an effect, the agent signs an invocation in JS (`signDocument(doc, seed,
   'capabilityInvocation', now)` with the chain embedded) and posts it to
   `/v1/invocations/evaluate`; dispatch only on `allow`, as in v1 (fail closed otherwise).
4. Store the returned bundle in the kernel event log; any later audit runs
   `verifyBundle(bundle, {trustedRoots: [humanDid], environmentDid})` offline. Revocations
   issued by the operator are posted to `/v1/revocations` and kept in the kernel's own store.
5. JARVIS's existing receipts/budgets stay authoritative for its own admission control; the
   cumulative ancestor-budget check means sibling agents share the delegated budget.

**Paperclip**

1. Paperclip agent key ids already use the v1 fingerprint format; the did:key of the same
   public key is derivable (`did from-key --public-key-file agent.pem`), so an agent keeps its
   key and gains a DID.
2. A company/owner root DID delegates per-agent capabilities (budget = the agent's spend cap,
   resources = the projects/issues it may touch); heartbeat runs carry the chain and sign
   invocations before consequential tool calls.
3. Revocation lists (`GET /v1/revocations`, or the records themselves) are synced into
   Paperclip so its own UI can show which agents lost authority; verification needs no Autheo
   uptime.

**Open questions for adopters:** where root keys live (hardware/OS keystore), what TTLs fit each
flow (shorter = less revocation lag), whether to publish revocation lists somewhere both sides
can read (git repo, object store), and whether did:web is needed for roots that must rotate.
