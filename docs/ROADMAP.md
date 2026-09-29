# Roadmap with verification gates

## Phase 0 — demonstrated locally

Signed agent passport → scoped mandate → signed request → allow/escalate/block →
DEMO budget accounting → signed receipt → checkpoint handoff → read-only MCP view.

Gate: tamper/context/expiry/replay/budget/concurrency tests plus real stdio checks
through both MCP launch methods. No live Autheo or wallet claim is permitted.

## Phase 1 — organizational identity and consent

Integrate OIDC owner authentication and workload identity (SPIFFE/SPIRE where
appropriate); separate issuer and runtime roles. A reviewed structured mandate
records owner, agent key, exact resources, allowed actions, environment, expiry,
policy version, risk threshold and revocation reference. Build a review queue with
human decisions bound to one immutable request digest and expiry.

Gate: an agent cannot enroll its own owner, extend scope or self-approve. Revocation
and key rotation are proven across two independent runtimes and restarted services.

## Phase 2 — real environment admission / transition

Implement runtime adapters for the actual agent host (OpenClaw, container worker,
or another chosen runtime). Bind checkpoints to artifact digests and environment
capabilities. Reauthenticate at the destination; fetch fresh local secrets from a
credential broker. Fence/suspend the source before resuming the destination.

Gate: crash/retry tests prove no double resume or duplicated side effect; wrong
image, untrusted artifact, expired grant and unreachable revocation service fail
closed. No secrets cross in a checkpoint bundle.

## Phase 3 — governed Autheo read execution

Route selected DevHub/Marketplace reads through a real policy enforcement point,
using service-specific credentials. Adopt OPA/Cedar-like policy evaluation behind
a versioned interface rather than growing the demo evaluator into a general engine.

Gate: tool bypass cannot evade enforcement; subject, resource, tenant, team and
credential audiences are checked at the actual service boundary. Existing MCP
read-only behavior remains available without the optional trust integration.

## Phase 4 — wallet and payments (separate signer)

Use an operator-approved Autheo-compatible signer, governed key custody, explicit
asset/network/recipient allowlists, exact base units, max fees, budget reservation,
idempotency, commit/release and reconciliation. Identity Ed25519 keys here are
**not** Autheo transaction-signing keys. Integrate only against documented live
settlement contracts and testnet endpoints first.

Gate: tests cover key isolation, cap enforcement under concurrency, wrong chain,
wrong asset, fee growth, replayed transaction intents, failed/uncertain submission,
reorg/finality and refunds. A human approves real-funds activation separately.

## Phase 5 — externally verifiable assurance

Export signed receipt digests to a privacy-reviewed transparency service or
append-only store; optionally anchor batches on-chain. Retain execution evidence
from the real executor and link its digest to the mandate and final receipt.

Gate: independent verifier detects modified events, missing tails, rollback and
conflicting heads. Evidence distinguishes requested, authorized, submitted,
executed, settled and reversed states. Only then consider stronger audit claims.

## Phase 6 — agent-to-agent economy

Add authenticated agent discovery, task negotiation and narrow delegated grants.
MCP supplies tools/context; an A2A-style protocol handles cross-agent task lifecycle.
Wallet/payment adapters remain optional and separately governed.

Gate: delegation can only attenuate; unknown agents and cross-tenant requests are
isolated; retries and disputes have attributable, independently checkable receipts.
