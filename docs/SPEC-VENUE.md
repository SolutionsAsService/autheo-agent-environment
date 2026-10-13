# Agents at external trading venues (`dex.*` scopes, v2 profile)

Status: 0.6, tested, not a stable contract. Builds on [SPEC-DID.md](SPEC-DID.md) (delegations,
invocations, receipts, bundles) and [POLICY.md](POLICY.md). Machine-checked by
`tests/vectors/autheo-v2-venue-vectors.json` (Python and `interop/js`).

An **external venue** is any DEX, exchange or order router that lets an agent quote or prepare
trades for a person. The venue plays the role of an *environment*: it verifies the agent's
invocation and delegation chain offline, decides allow / escalate / block, and signs a receipt.
The person (the **principal**, root DID of the chain) keeps their account keys; agents never
receive them.

## 1. Scopes

| scope | the agent asks the venue to... | amount_minor |
|---|---|---|
| `dex.quote` | price a trade or route (read only) | 0 |
| `dex.policy_check` | explain whether a transfer would pass the asset's rules (read only) | 0 |
| `dex.order.build` | build an **unsigned** order for the principal to sign | what the principal gives up |
| `dex.order.sign` | present a built order to the principal for signature | same as the order |

`dex.order.sign` never means "sign for me": no conforming venue signs on a principal's behalf or
accepts a principal's private key from an agent. Grant it only to agents that may put orders in
front of the principal.

## 2. Resources and amounts

* **Resource**: `chain:<chain-id>:asset:<asset-id>`, e.g. `chain:31337:asset:RWA1`. `chain-id` is
  the venue's chain name or EIP-155 number; `asset-id` its asset id or lowercase token address.
  Because grant patterns are prefixes, `chain:31337:*` grants every asset on one chain and
  `chain:*` every chain (section 4 of SPEC-DID.md).
* **Budget asset**: capabilities and invocations carry `asset` (pattern
  `^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$`, default `DEMO`). It names the unit of **every**
  `*_minor` amount: per-action limit, total budget, approval threshold and the invocation's
  `amount_minor`. Venues use e.g. `erc20:<lowercase token address>`.
* A child delegation MUST keep its parent's `asset` (otherwise `attenuation_violation`; issuers
  refuse to sign it). An invocation whose `asset` differs from the leaf capability's is blocked
  with `asset_mismatch`. Receipts record `asset`; bundle verifiers bind it (missing = `DEMO`).

## 3. What a venue MUST do

1. **Verify offline.** `verifyInvocation` (JS) / `verify_invocation` (Python) with the venue's
   pinned principal roots and every revocation record it has accepted. A forged, tampered or
   mis-signed invocation or chain is **rejected** and not recorded.
2. **Bind the invocation to the call.** `action`, `resource`, `amount_minor` and `asset` of the
   invocation must equal what the venue is asked to do; otherwise refuse. `environment` must be
   the venue's own id (`wrong_environment`). The request id is an idempotency key: the same
   invocation returns the earlier decision, a different one with a reused id is refused.
3. **Decide** with the mandate-only policy: `decideInvocation` (JS) / `decide_invocation`
   (Python). Reasons and precedence (block > escalate > allow) are those of POLICY.md, plus
   `asset_mismatch`. Mapping:
   * `allow` - proceed (quote, explain, or return the unsigned order);
   * `escalate` - return a *needs human approval* plan naming the principal and the reasons;
     nothing is counted against budgets;
   * `block` - refuse with the reasons.
4. **Bind the order to the invocation.** An order built for an agent carries the invocation
   digest (`document_digest` of the receipt) in a field the principal signs, so the signer sees
   which agent asked, and settlement records link back to the receipt.
5. **Record.** Sign one `autheo.receipt/v2` per decision with the venue's did:key
   (`signDecisionReceipt`), hash-link them (`chainHash`) and be able to export
   `autheo.ledger-export/v2`. A receipt plus its invocation is a bundle any third party can
   check with `verifyBundle` / `python -m autheo_agent_environment.verifier bundle`.

## 4. Vectors

`tests/vectors/autheo-v2-venue-vectors.json` (generate/check:
`python -m autheo_agent_environment vectors-venue generate|check <path>`): a principal -> agent ->
sub-agent chain with a cash budget, and decision cases for allow, escalate, per-action / total /
ancestor budgets, an undelegated `dex.order.sign`, other asset, other chain, budget-asset
mismatch, a forged widened chain, a revoked chain, an untrusted root, a wrong venue, a tampered
invocation and a forged chain; plus venue-signed receipts, a ledger export and bundles.
`node interop/js/verify-venue-vectors.mjs` checks that the JS package reproduces every
decision and signs byte-identical receipts.

## 5. Limits

* Budgets are per decider: a venue only sees its own receipts. Spend across several venues is
  only capped if they share an environment (or the principal splits the budget per venue).
* The JS decision implements the built-in mandate-only policy only; declarative
  `autheo.policy/v1` rules need the Python decision point.
* Binding a principal DID to a wallet or account is the venue's job (not specified here); the
  principal's own signature on the order remains the final authority.
* Receipts keep `executed: false`: they record an authorization decision, not a trade.
