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
what it did. Autheo never executes anything, never holds funds and issues no DIDs.

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
* No DID, VC, wallet, payment, chain anchoring or Autheo platform service is involved.
