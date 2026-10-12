# Threat model and limits

This is a single-host reference prototype, not a production security boundary.
A local operator who controls the process, signing keys, configured public keys
or database is trusted. Never give an untrusted agent shell access to that process
or its key material and expect this library to contain it.

## Enforced and tested

- Foreign agent keys, unknown issuer/key ID, wrong subject/audience/environment,
  wrong token type/algorithm, future validity, expiry and overlong validity fail.
- `iat` / `nbf` claims allow at most two seconds of positive clock skew; expiry
  validation remains strict. Issuer and verifier clocks still need synchronization.
- Request signatures bind the proposed action to the passport's agent key.
- Strict integer DEMO budgets reject negative amounts, floats, booleans and strings.
- Scope/resource denial, cumulative cap, per-action cap, review threshold, local
  revocation and idempotency conflicts prevent new simulation reservations.
- Concurrent requests cannot race past a single SQLite mandate budget.
- Handoffs cannot widen source permissions or exceed destination allowlists;
  wrong destination/passport and replay fail. Extra checkpoint fields fail.
- Edited receipt chains fail signature/hash validation. A separately trusted head
  allows detection of missing tails. Signed summaries are not silently trusted
  by MCP when their key, actor, validity or structure is wrong.

## NOT solved

- **Real identity:** an owner ID is an issuer assertion, not KYC, legal ownership,
  proof of incorporation, or a verified human consent ceremony.
- **Production key custody:** demo keys live in process memory and disappear at exit.
  Issuer and environment receipt signer share one demo authority; production must
  separate these roles and use governed key storage/rotation.
- **Immutable audit:** a local administrator can delete, roll back or replace an
  entire database/archive. A local hash chain alone cannot detect a removed suffix
  without a trusted external checkpoint. There is no chain anchor or transparency log.
- **Perfect revocation:** MCP reads snapshots with at most 120 seconds of freshness,
  not instant authority status. Destination checkpoint import has no authoritative
  cross-environment revocation feed and grants no execution authority for that reason.
- **Real payments:** there are no wallet keys, THEO transfers, transaction signing,
  gas estimation, fee reservation, blockchain nonce management or settlement finality.
- **Executor enforcement:** policy decisions govern only this reference simulator.
  They do not enforce controls over existing MCP reads, arbitrary processes or APIs.
- **Agent sandbox / live migration:** none. A checkpoint isn't a running environment.
- **Approval UI / consent:** not implemented. Escalation remains pending; an agent
  cannot grant itself an approval by passing `approved=true` or another extra field.
- **Arbitrary evidence retention:** pre-auth malformed requests are rejected, not
  inserted into the signed receipt chain. No promise that every OS/network event is logged.
- **Production scale:** chain verification is linear in ledger length. Budget,
  revocation and checkpoint APIs are trusted local Python APIs, not a multi-tenant service.

## 0.2 service surfaces

Enforced and tested:

- The HTTP API binds loopback by default and refuses other addresses without an
  explicit `--allow-remote`; it checks a bearer token in constant time, requires a
  loopback Host header with the bound port (DNS rebinding) and same-origin
  `Origin`, sends no CORS headers, limits bodies to 64 KiB and rejects unknown fields.
- Policies come only from operator files and can only narrow mandates; tools must
  be exactly listed in a mandate; deny lists win; block > escalate > allow.
- Revocations, grants, identity issuance, decisions and outcome reports are signed
  receipts; ledger verification localises edited, reordered or deleted rows and
  detects truncation when given an independently stored anchor head.
- Agent-signed requests/outcomes must use the passport key's fingerprint as `kid`.

Not solved:

- **Token and key files:** `api-token`, `issuer-key.pem` and `agents/*.pem` are
  plaintext files protected only by filesystem permissions (best effort on
  Windows). Anyone who can read them can act as the operator or issuer.
- **Service-held agent keys** (`--generate-key`) remove proof-of-possession: the
  service signs on the agent's behalf. Use agent-held keys for real integrations.
- **Append-only triggers** only stop accidental edits; a local admin can drop them.
- **No TLS or per-caller authorization:** one token grants every API operation,
  including mandate grants. Do not expose the API to agents that must not grant
  themselves authority; give agents a separate path that can only evaluate.
- **Outcome receipts** record what an executor claims; they do not prove execution.
- **Policy reload, rollout and rollback** are manual (restart); receipts record the
  policy digest so changes stay auditable.

## Safe deployment boundary for later work

Use separate identities for the owner issuer, runtime attestor, policy decision
service, credential broker and wallet signer. Keep trust anchors/configuration
operator-controlled. Pass only least-privilege, audience-bound credentials. An
actual executor must recheck authorization immediately before committing an action;
it cannot accept an old MCP snapshot or a policy preview as a spendable capability.

Production security review must examine key compromise, confused deputy attacks,
TOCTOU, storage rollback, replay across replicas, policy rollback, retries,
partial external execution, revocation races and recovery from a failed handoff.


## v2: DIDs and delegation chains (0.3.0)

What a v2 verifier relies on: Ed25519, SHA-256, the root DID(s) it pins, the environment DID it
pins (for receipts), its own clock, and the revocation records it holds. Nothing else - no
registry, issuer service or network.

| Threat | What happens | Residual risk / mitigation |
| --- | --- | --- |
| **Chain forgery** (invented or edited links, swapped parents, an impostor issuing below someone else's grant) | Every link's proof is checked against its issuer's did:key; each link names its parent by id **and digest** and must be issued by the parent's subject; tampering yields `bad_signature`/`broken_link` and is rejected (tested incl. property tests). | None known within the profile; forging requires a private key. |
| **Privilege widening** by a correctly signed child | Attenuation is checked at issuance (refused) **and** by every verifier (`attenuation_violation`, `depth_exceeded`) - verifiers never trust the issuer's tooling. | Pattern semantics are deliberately simple (exact, `prefix*`, `*`); richer caveats are not supported. |
| **Key compromise of an agent** | The thief can act within that agent's delegated capability until the link expires or is revoked; it cannot widen it. The parent (or any ancestor) revokes; the agent can also renounce. | Exposure window = time until revocation reaches each verifier, capped by the link's validity (max 30 days, CLI default 1 h). Use short TTLs and re-delegate. |
| **Key compromise of a root** | The thief can issue new chains under that root. | Relying parties must re-pin a new root; the old root's revocations help only verifiers that receive them. Keep root keys offline/hardware-backed (not implemented here); prefer did:web for roots that need rotation. |
| **Compromise of the environment key** | Receipts and the v2 ledger can be rewritten or forged by the key holder (same as v1). | Store ledger heads elsewhere (`--expected-head`). Bundles still re-check the chain: a forged `allow` receipt cannot be backed by a chain unless the root/agent keys are also compromised. |
| **Replay** | Invocations expire within 300 s; each environment records one decision per request id (same document = replay of the stored receipt, different = conflict). | An offline verifier cannot detect replays across environments or ledgers it does not see; idempotency is per environment ledger. |
| **Clock skew** | Two seconds of skew are tolerated for `validFrom/created`; expiry is strict. Bundles are evaluated at the receipt's `recorded_at`. | A verifier with a wrong clock can accept expired links or reject fresh ones; historical checks trust the environment's `recorded_at`. |
| **Revocation lag** | Revocations are effective only where they are known: environments apply every record they accepted; offline verifiers apply the records they are given. | **Inherent to permissionless, offline verification.** Bound it with short TTLs, distribute lists (ledger export, revocation list, bundles), and have high-stakes verifiers fetch fresh lists before accepting. There is no freshness proof. |
| **Backdated revocation** | `revoked_at` is asserted by the revoker; an entitled revoker could make past decisions look unauthorized. | The ledger receipt order shows when the environment learned of it. |
| **Revocation spam** | Anyone may submit records, but only records by an entitled DID (issuer of the link or an ancestor, or the link's subject) have an effect. | Storage growth of unentitled records (they are stored and receipted). |
| **did:web takeover** | Whoever controls the domain/TLS controls the DID. Resolution is offline by default (cached/pinned documents), fetch is opt-in. | Live did:web resolution is untested; pin documents (`did web-cache add`) for anything important. |
| **Local-dev custody** | `POST /v1/dids` keeps private keys as unencrypted files in the state dir for demos. | Never use service-held keys for real authority; real agents sign their own documents. |
