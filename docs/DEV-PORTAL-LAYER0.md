# Dev Portal / Layer 0 integration design

Status: **planned integration**, not a connected service. “Layer 0” denotes the target Autheo platform layer in this design, not an asserted protocol or deployed contract. Confirm the platform's actual APIs, identity model, chain/network IDs, and finality rules before implementing adapters.

## Component boundaries

| Component | Responsibility | Current state |
| --- | --- | --- |
| Dev Portal | Human authentication, agent registration, mandate review, environment selection | Target integration; no portal adapter yet |
| Agent Environment | Signed passports/mandates, policy, simulated budgets, checkpoint receipts | Local Python reference implementation |
| Autheo MCP | Read-only inspection of bounded signed trust snapshots | Implemented, optional trust extra |
| Runtime adapter | Recheck fresh authority, isolate workloads, invoke approved operation | Not implemented |
| Wallet / signer | Enforce asset/recipient/network caps at signing boundary | Not implemented; DEMO only |
| Layer 0 adapter | Platform identity/registry and optional audit anchoring | Proposed; requires validated platform contract |
| Explanatory website | Public architecture, educational policy example, docs | Static, no credentials or authority |

## Intended flow

1. A human signs into the Dev Portal using its existing authentication. Keep browser sessions separate from workload identity.
2. An authorized backend issues an agent passport and a short-lived, resource-scoped mandate, bound to tenant, environment and agent public key. Never expose issuer private keys to a browser or MCP client.
3. The workload signs its request. A trusted execution boundary verifies signature, expiry, revocation, audience, resource and budget **at execution time**. An MCP snapshot is not authorization.
4. A future runtime adapter submits only approved operations through documented Dev Portal/platform APIs. Use server-generated idempotency keys and reserve/commit/release accounting tied to authoritative operation outcomes; an accepted request is not a completed deployment or payment.
5. Record signed receipts with request and outcome digests. If Layer 0 supports anchoring, publish only an approved minimal hash commitment through a separately authorized signer. Keep identities, prompts, tokens and private payloads off-chain.
6. On environment transition, transfer allowlisted checkpoint references and digests. The destination independently authenticates the agent, obtains a fresh narrower mandate and checks revocation. The current prototype imports no runtime, funds, secrets or execution authority.

## Integration gates

- Obtain actual platform API specifications and sandbox endpoints; no guessed routes.
- Map portal tenants/roles to issuers and workloads; enforce tenant isolation.
- Define trusted key storage, rotation, revocation distribution and emergency stop.
- Specify policy versioning, approval separation and reservation reconciliation.
- Prove negative cases: stale/revoked grants, replay, duplicate operation, cross-tenant/resource requests, rollback, partial failure and concurrency.
- Verify receipts against actual execution outcomes and independent audit heads.
- Complete security review before enabling wallets, payments or live workloads.

## Repositories

- [MCP](https://github.com/ThothDivision/autheo-mcp)
- [Agent Environment](https://github.com/SolutionsAsService/autheo-agent-environment)
- [Explanatory site](https://github.com/SolutionsAsService/autheo-agent-environment-site)

Built by SolutionsAsService. This document is a handoff plan, not evidence of live integration.
