# Threat model and limits

This is a single-host reference prototype, not a production security boundary.
A local operator who controls the process, signing keys, configured public keys
or database is trusted. Never give an untrusted agent shell access to that process
or its key material and expect this library to contain it.

## Enforced and tested

- Foreign agent keys, unknown issuer/key ID, wrong subject/audience/environment,
  wrong token type/algorithm, future validity, expiry and overlong validity fail.
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

## Safe deployment boundary for later work

Use separate identities for the owner issuer, runtime attestor, policy decision
service, credential broker and wallet signer. Keep trust anchors/configuration
operator-controlled. Pass only least-privilege, audience-bound credentials. An
actual executor must recheck authorization immediately before committing an action;
it cannot accept an old MCP snapshot or a policy preview as a spendable capability.

Production security review must examine key compromise, confused deputy attacks,
TOCTOU, storage rollback, replay across replicas, policy rollback, retries,
partial external execution, revocation races and recovery from a failed handoff.
