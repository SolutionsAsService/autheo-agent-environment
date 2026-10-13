"""Deterministic v2 venue vectors (tests/vectors/autheo-v2-venue-vectors.json).

An agent asks an external trading venue (a DEX or exchange) to quote or build an order using the
dex.* scopes (docs/SPEC-VENUE.md). Each decision case holds the invocation, the venue's earlier
decisions (history) and the outcome computed by the Python reference (didenv.decide_invocation,
mandate-only policy). The venue's own signed receipts and bundles are included so a venue can
prove its records verify offline. interop/js/verify-venue-vectors.mjs must agree with every case.
Seeds are PUBLIC TEST VALUES; ids and timestamps are fixed.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from .canonical import ZERO_HASH
from .data_integrity import ProofError, add_proof
from .delegation import issue_delegation, issue_invocation, issue_revocation, verify_invocation
from .did import DidKey, Resolver
from .didenv import decide_invocation
from .policy import DEFAULT_POLICY
from .vectors_v2 import _forge, _uuid
from .verifier import v2_chain_hash, verify_bundle, verify_receipts

VECTOR_VERSION = "autheo-test-vectors/v2-venue"
NOW = 1_790_100_000
VENUE = "venue:example-dex"
CASH = "erc20:0x00000000000000000000000000000000000000c5"  # budget denomination (minor units)
ASSET = "chain:31337:asset:RWA1"
PRINCIPAL_CAP = {"environments": ["venue:*"], "scopes": ["dex.quote", "dex.policy_check", "dex.order.build"],
                 "resources": ["chain:31337:asset:*"], "asset": CASH, "per_action_minor": 100_000,
                 "total_budget_minor": 150_000, "approval_threshold_minor": 50_000, "max_delegation_depth": 1}
AGENT_CAP = {"environments": [VENUE], "scopes": ["dex.quote", "dex.order.build"], "resources": [ASSET],
             "asset": CASH, "per_action_minor": 60_000, "total_budget_minor": 100_000,
             "approval_threshold_minor": 40_000, "max_delegation_depth": 0}


def _key(label: str) -> DidKey:
    return DidKey.from_seed(hashlib.sha256(f"autheo-test-vector-seed:v2-venue:{label}".encode()).digest())


def build() -> dict:  # noqa: PLR0915 - one linear fixture script
    principal, agent, sub, stranger, venue = (_key(n) for n in ("principal", "agent", "subagent", "stranger", "venue"))
    keys = {name: {"did": key.did, "TEST_ONLY_seed_hex": key.seed().hex()} for name, key in
            [("principal", principal), ("agent", agent), ("subagent", sub), ("stranger", stranger), ("venue", venue)]}
    d1 = issue_delegation(principal.signer, agent.did, PRINCIPAL_CAP, valid_from=NOW, valid_until=NOW + 7200,
                          delegation_id=_uuid(401))
    d2 = issue_delegation(agent.signer, sub.did, AGENT_CAP, valid_from=NOW, valid_until=NOW + 3600, parent=d1,
                          delegation_id=_uuid(402))
    widened = _forge(agent.signer, sub.did, {**AGENT_CAP, "scopes": ["dex.quote", "dex.order.build", "dex.order.request_signature"],
                                             "resources": ["chain:*"]},
                     valid_from=NOW, valid_until=NOW + 3600, parent=d1, number=421)
    foreign = _forge(stranger.signer, sub.did, AGENT_CAP, valid_from=NOW, valid_until=NOW + 3600, parent=d1,
                     number=422)
    revoked = issue_revocation(principal.signer, d2, revoked_at=NOW + 5, revocation_id=_uuid(411))

    def invoke(name, action, resource=ASSET, amount=0, *, asset=CASH, chain=(d1, d2), environment=VENUE):
        return issue_invocation(sub.signer, list(chain), request_id=f"req:venue-{name}", environment=environment,
                                action=action, resource=resource, amount_minor=amount, created=NOW + 10, asset=asset)

    def spent(amount, chain):
        return {"kind": "decision", "decision": "allow", "amount_minor": amount, "action": "dex.order.build",
                "tool": None, "recorded_at": NOW + 1, "chain": [{"id": link["id"]} for link in chain]}

    def case(name, invocation, *, history=(), roots=(principal.did,), revocations=(), at=NOW + 20):
        roots = None if roots is None else list(roots)
        item = {"name": name, "invocation": invocation, "at": at, "trusted_roots": roots,
                "revocations": list(revocations), "history": list(history)}
        try:
            result = verify_invocation(invocation, resolver=Resolver(), at=at, trusted_roots=roots,
                                       revocations=list(revocations))
            decision = decide_invocation(result, invocation, environment_id=VENUE, policy=DEFAULT_POLICY,
                                         receipts=list(history), at=at)
        except ProofError as error:
            return {**item, "expect_error": error.code}
        return {**item, "expect_error": None, "expect_decision": decision.decision,
                "expect_reasons": list(decision.reasons), "expect_digest": result.digest}

    tampered = copy.deepcopy(invoke("tampered", "dex.order.build", amount=30_000))
    tampered["amount_minor"] = 3_000
    decision_cases = [
        case("quote_allow", invoke("quote", "dex.quote")),
        case("order_build_allow", invoke("build-allow", "dex.order.build", amount=30_000)),
        case("order_build_escalate", invoke("build-escalate", "dex.order.build", amount=50_000)),
        case("order_build_over_per_action", invoke("build-per-action", "dex.order.build", amount=70_000)),
        case("order_build_over_total_budget", invoke("build-total", "dex.order.build", amount=50_000),
             history=[spent(60_000, [d1, d2])]),
        case("order_build_over_ancestor_budget", invoke("build-ancestor", "dex.order.build", amount=20_000),
             history=[spent(140_000, [d1])]),
        case("order_sign_not_delegated", invoke("sign", "dex.order.request_signature", amount=30_000)),
        case("other_asset", invoke("other-asset", "dex.quote", resource="chain:31337:asset:RWA2")),
        case("other_chain", invoke("other-chain", "dex.quote", resource="chain:1:asset:RWA1")),
        case("budget_asset_mismatch", invoke("asset", "dex.order.build", amount=30_000,
                                             asset="erc20:0x00000000000000000000000000000000000000d1")),
        case("widened_chain", invoke("widened", "dex.order.request_signature", amount=30_000, chain=(d1, widened))),
        case("revoked_chain", invoke("revoked", "dex.order.build", amount=30_000), revocations=[revoked]),
        case("untrusted_root", invoke("untrusted", "dex.quote"), roots=(stranger.did,)),
        case("wrong_venue", invoke("wrong-venue", "dex.quote", environment="venue:other")),
        case("tampered_invocation", tampered),
        case("forged_chain", invoke("forged", "dex.quote", chain=(d1, foreign))),
    ]

    receipts, previous, invocations = [], ZERO_HASH, {}
    for sequence, name in enumerate(["order_build_allow", "order_build_escalate", "order_sign_not_delegated"], 1):
        item = next(c for c in decision_cases if c["name"] == name)
        invocation = item["invocation"]
        result = verify_invocation(invocation, resolver=Resolver(), at=NOW + 20, trusted_roots=[principal.did])
        recorded_at = NOW + 20 + sequence
        body = {"type": "AutheoReceipt", "schema_version": "autheo.receipt/v2", "id": _uuid(500 + sequence),
                "issuer": venue.did, "environment": VENUE, "sequence": sequence, "previous_hash": previous,
                "recorded_at": recorded_at, "kind": "decision", "decision": item["expect_decision"],
                "reasons": item["expect_reasons"], "document_digest": result.digest, "request_id": invocation["id"],
                "invoker": invocation["invoker"], "root": result.chain.root,
                "chain": [{k: link[k] for k in ("id", "digest", "issuer", "subject")} for link in result.chain.links],
                "action": invocation["action"], "resource": invocation["resource"],
                "amount_minor": invocation["amount_minor"], "asset": invocation["asset"],
                "policy_id": DEFAULT_POLICY.policy_id, "policy_digest": DEFAULT_POLICY.digest,
                "executed": False, "simulation_only": True}
        receipt = add_proof(body, venue.signer, "assertionMethod", recorded_at)
        receipts.append(receipt)
        invocations[name] = invocation
        previous = v2_chain_hash(previous, receipt)
    ledger = {"schema_version": "autheo.ledger-export/v2", "environment": VENUE, "issuer": venue.did,
              "head": previous, "receipts": receipts}
    assert verify_receipts(receipts, resolver=Resolver(), issuer=venue.did, environment=VENUE)["valid"]

    def bundle_case(name, receipt, invocation):
        bundle = {"schema_version": "autheo.bundle/v2", "receipt": receipt, "invocation": invocation, "revocations": []}
        report = verify_bundle(bundle, resolver=Resolver(), trusted_roots=[principal.did], environment_did=venue.did)
        return {"name": name, "bundle": bundle, "trusted_roots": [principal.did], "environment_did": venue.did,
                "expect_valid": report["valid"], "expect_verdict": report.get("verdict"),
                "expect_problems": report["problems"]}

    edited = copy.deepcopy(receipts[1])
    edited["decision"] = "allow"
    bundle_cases = [
        bundle_case("allow_verified", receipts[0], invocations["order_build_allow"]),
        bundle_case("escalate_verified", receipts[1], invocations["order_build_escalate"]),
        bundle_case("block_verified", receipts[2], invocations["order_sign_not_delegated"]),
        bundle_case("edited_decision", edited, invocations["order_build_escalate"]),
    ]
    refused = []
    for label, capability in [("scope", {**AGENT_CAP, "scopes": ["dex.quote", "dex.order.request_signature"]}),
                              ("budget", {**AGENT_CAP, "per_action_minor": 100_001, "total_budget_minor": 150_001}),
                              ("asset", {**AGENT_CAP, "asset": "DEMO"})]:
        try:
            issue_delegation(agent.signer, sub.did, capability, valid_from=NOW, valid_until=NOW + 60, parent=d1)
        except ValueError:
            refused.append(label)
    assert refused == ["scope", "budget", "asset"], refused  # issuing a widening is refused, not just detected
    return {
        "version": VECTOR_VERSION,
        "spec": "docs/SPEC-VENUE.md",
        "warning": "TEST_ONLY seeds are public; never use them for real keys.",
        "now": NOW,
        "venue": VENUE,
        "policy": {"policy_id": DEFAULT_POLICY.policy_id, "policy_digest": DEFAULT_POLICY.digest},
        "keys": keys,
        "delegations": {"principal_to_agent": d1, "agent_to_subagent": d2, "widened": widened},
        "revocations": {"principal_revokes_agent_to_subagent": revoked},
        "decision_cases": decision_cases,
        "ledger": ledger,
        "bundle_cases": bundle_cases,
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write(path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(render(), encoding="utf-8")
