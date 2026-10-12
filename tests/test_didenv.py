"""v2 environment ledger / PDP and the offline bundle and ledger verifiers."""

from __future__ import annotations

import copy
import json
import sqlite3
import time
from contextlib import closing

import pytest

from autheo_agent_environment.data_integrity import ProofError
from autheo_agent_environment.delegation import (
    issue_delegation,
    issue_invocation,
    issue_revocation,
)
from autheo_agent_environment.did import DidKey, Resolver
from autheo_agent_environment.didenv import ChainRejected, DelegationLedger
from autheo_agent_environment.environment import Environment
from autheo_agent_environment.errors import ConflictError
from autheo_agent_environment.signing import Signer
from autheo_agent_environment.verifier import main as verifier_main
from autheo_agent_environment.verifier import verify_bundle, verify_receipts

ROOT, AGENT, SUB, STRANGER = (DidKey.from_seed(bytes([i]) * 32) for i in (1, 2, 3, 4))
ROOT_CAP = dict(environments=["env:*"], scopes=["compute.simulate", "marketplace.read"], resources=["listing:*"],
                per_action_minor=80, total_budget_minor=100, approval_threshold_minor=50, max_delegation_depth=2)
SUB_CAP = dict(environments=["env:research"], scopes=["compute.simulate"], resources=["listing:demo-01"],
               per_action_minor=60, total_budget_minor=90, approval_threshold_minor=40, max_delegation_depth=0)


@pytest.fixture
def world():
    now = int(time.time())
    environment = Environment.ephemeral("env:research", Signer.generate("autheo-test-authority"))
    ledger = DelegationLedger(environment, trusted_roots=[ROOT.did])
    d1 = issue_delegation(ROOT.signer, AGENT.did, ROOT_CAP, valid_from=now - 10, valid_until=now + 3600)
    d2 = issue_delegation(AGENT.signer, SUB.did, SUB_CAP, valid_from=now - 10, valid_until=now + 1800, parent=d1)
    counter = iter(range(1, 1000))

    def invoke(chain=None, signer=SUB, **overrides):
        fields = dict(request_id=f"req:{next(counter)}", environment="env:research", action="compute.simulate",
                      resource="listing:demo-01", amount_minor=10, created=now)
        fields.update(overrides)
        return issue_invocation(signer.signer, chain or [d1, d2], **fields)

    yield {"env": environment, "ledger": ledger, "chain": [d1, d2], "invoke": invoke, "now": now}
    environment.close()


def test_allow_escalate_block_and_explanations(world):
    ledger, invoke = world["ledger"], world["invoke"]
    allow = ledger.evaluate(invoke(amount_minor=30))
    assert allow["receipt"]["decision"] == "allow" and allow["decision"].decision == "allow"
    checks = {e.check: e.outcome for e in allow["decision"].explanation}
    assert checks["chain.verified"] == "pass" and checks["chain.environment"] == "pass"
    assert checks["chain.budget:0"] == "pass"
    escalate = ledger.evaluate(invoke(amount_minor=45))
    assert escalate["receipt"]["reasons"] == ["human_review_required"]
    block = ledger.evaluate(invoke(action="marketplace.read"))  # granted to the agent, not to the sub-agent
    assert block["receipt"]["decision"] == "block" and block["receipt"]["reasons"] == ["scope_denied"]
    receipt = allow["receipt"]
    assert receipt["root"] == ROOT.did and receipt["invoker"] == SUB.did and receipt["issuer"] == ledger.did
    assert [link["subject"] for link in receipt["chain"]] == [AGENT.did, SUB.did]
    assert receipt["executed"] is False and receipt["simulation_only"] is True


def test_ancestor_budgets_count_everything_spent_below_them(world):
    ledger, invoke, now = world["ledger"], world["invoke"], world["now"]
    d1, d2 = world["chain"]
    sibling = issue_delegation(AGENT.signer, STRANGER.did, SUB_CAP, valid_from=now - 10, valid_until=now + 1800,
                               parent=d1)
    assert ledger.evaluate(invoke(amount_minor=40))["receipt"]["decision"] == "allow"
    assert ledger.evaluate(invoke([d1, sibling], signer=STRANGER, amount_minor=40))["receipt"]["decision"] == "allow"
    # 80 of the root's 100 is spent across both sub-agents; 30 more exceeds the ROOT delegation's total.
    result = ledger.evaluate(invoke(amount_minor=30))
    assert result["receipt"]["decision"] == "block"
    assert "chain_budget_limit:0" in result["receipt"]["reasons"]


def test_authentic_but_unauthorised_chains_are_recorded_as_blocks(world):
    ledger, invoke = world["ledger"], world["invoke"]
    d1, d2 = world["chain"]
    ledger.trusted_roots = {STRANGER.did}
    result = ledger.evaluate(invoke())
    assert result["receipt"]["decision"] == "block"
    assert result["receipt"]["reasons"][0] == "delegation_untrusted_root:0"
    ledger.trusted_roots = {ROOT.did}
    revocation = issue_revocation(AGENT.signer, d2, revoked_at=world["now"] - 1)
    recorded = ledger.record_revocation(revocation)
    assert recorded["kind"] == "revocation" and recorded["reference"] == revocation["id"]
    assert ledger.record_revocation(revocation)["replayed"] is True
    blocked = ledger.evaluate(invoke())
    assert blocked["receipt"]["reasons"][0] == "delegation_revoked:1"
    assert blocked["bundle"]["revocations"] == [revocation]
    other = copy.deepcopy(revocation)
    other["reason"] = "compromised"
    with pytest.raises(ConflictError):
        ledger.record_revocation(issue_revocation(AGENT.signer, d2, revoked_at=world["now"],
                                                  revocation_id=revocation["id"]))


def test_forged_chains_and_invocations_are_rejected_not_recorded(world):
    ledger, invoke = world["ledger"], world["invoke"]
    d1, d2 = world["chain"]
    forged = copy.deepcopy(d2)
    forged["credentialSubject"]["capability"]["total_budget_minor"] = 100
    with pytest.raises(ChainRejected) as error:
        ledger.evaluate(invoke([d1, forged]))
    assert error.value.errors[0]["code"] == "bad_signature"
    tampered = invoke()
    tampered["amount_minor"] = 1
    with pytest.raises(ProofError):
        ledger.evaluate(tampered)
    with pytest.raises(ValueError, match="different environment"):
        ledger.evaluate(invoke(environment="env:review"))
    with pytest.raises(ProofError):
        ledger.evaluate("not a dict")
    assert ledger.receipts() == []


def test_idempotent_replay_and_conflicting_reuse(world):
    ledger, invoke = world["ledger"], world["invoke"]
    invocation = invoke(request_id="req:same")
    first = ledger.evaluate(invocation)
    again = ledger.evaluate(invocation)
    assert again["receipt"]["replayed"] is True and again["decision"] is None
    assert again["receipt"]["id"] == first["receipt"]["id"]
    with pytest.raises(ConflictError):
        ledger.evaluate(invoke(request_id="req:same", amount_minor=11))
    assert len(ledger.receipts()) == 1


def test_bundles_verify_offline_and_detect_tampering(world):
    ledger, invoke = world["ledger"], world["invoke"]
    bundle = ledger.evaluate(invoke(amount_minor=20))["bundle"]
    resolver = Resolver()
    report = verify_bundle(bundle, resolver=resolver, trusted_roots=[ROOT.did], environment_did=ledger.did)
    assert report["valid"] and report["verdict"] == "allow_verified" and report["authorized_by_chain"]
    assert report["network_used"] is False and report["chain"]["depth"] == 2
    assert not verify_bundle(bundle, resolver=resolver, trusted_roots=[STRANGER.did])["valid"]
    assert verify_bundle(bundle, resolver=resolver, trusted_roots=None)["root_pinned"] is False
    wrong_env = verify_bundle(bundle, resolver=resolver, trusted_roots=[ROOT.did], environment_did=ROOT.did)
    assert wrong_env["problems"] == ["receipt_invalid:untrusted_issuer"]

    edited = copy.deepcopy(bundle)
    edited["receipt"]["decision"] = "block"
    assert verify_bundle(edited, resolver=resolver)["problems"] == ["receipt_invalid:bad_signature"]
    swapped = copy.deepcopy(bundle)
    swapped["invocation"] = invoke(amount_minor=20)
    assert verify_bundle(swapped, resolver=resolver)["problems"] == ["invocation_digest_mismatch"]
    assert verify_bundle({"receipt": 1}, resolver=resolver)["problems"][0].startswith("malformed_bundle")

    revoked = issue_revocation(ROOT.signer, world["chain"][0], revoked_at=bundle["receipt"]["recorded_at"] - 5)
    late = verify_bundle(bundle, resolver=resolver, trusted_roots=[ROOT.did], extra_revocations=[revoked])
    assert late["problems"] == ["allow_not_supported_by_chain"] and late["authorized_by_chain"] is False


def test_block_bundles_are_verifiable_facts(world):
    ledger, invoke = world["ledger"], world["invoke"]
    bundle = ledger.evaluate(invoke(action="marketplace.read"))["bundle"]
    report = verify_bundle(bundle, resolver=Resolver(), trusted_roots=[ROOT.did])
    assert report["valid"] and report["verdict"] == "block_verified" and report["request_problems"] == ["scope_denied"]


def test_v2_ledger_export_verifies_and_detects_edits(world, tmp_path):
    ledger, invoke = world["ledger"], world["invoke"]
    for amount in (10, 20, 30):
        ledger.evaluate(invoke(amount_minor=amount))
    export = ledger.export()
    report = verify_receipts(export["receipts"], resolver=Resolver(), issuer=ledger.did, environment="env:research")
    assert report["valid"] and report["head"] == export["head"] and report["count"] == 3
    assert ledger.verify(expected_head=export["head"])["anchor_matches"] is True
    assert not ledger.verify(expected_head="0" * 64)["valid"]
    reordered = verify_receipts(export["receipts"][::-1], resolver=Resolver(), issuer=ledger.did)
    assert not reordered["valid"] and reordered["first_invalid_sequence"] == 1
    truncated = verify_receipts(export["receipts"][:2], resolver=Resolver(), issuer=ledger.did,
                                expected_head=export["head"])
    assert "head_differs_from_anchor" in [p["problem"] for p in truncated["problems"]]
    foreign = verify_receipts(export["receipts"], resolver=Resolver(), issuer=ROOT.did)
    assert foreign["problems"][0]["problem"] == "receipt_invalid:untrusted_issuer"

    path = tmp_path / "export.json"
    path.write_text(json.dumps(export))
    assert verifier_main(["ledger", str(path), "--issuer", ledger.did]) == 0
    export["receipts"][1]["amount_minor"] = 99
    path.write_text(json.dumps(export))
    assert verifier_main(["ledger", str(path), "--issuer", ledger.did]) == 1


def test_sqlite_edits_break_the_v2_chain(world):
    ledger, invoke = world["ledger"], world["invoke"]
    ledger.evaluate(invoke())
    ledger.evaluate(invoke())
    with closing(sqlite3.connect(world["env"].path)) as db:
        row = db.execute("SELECT document FROM v2_events WHERE sequence=1").fetchone()
        receipt = json.loads(row[0])
        receipt["decision"] = "block"
        db.execute("UPDATE v2_events SET document=? WHERE sequence=1", (json.dumps(receipt),))
        db.commit()
    assert not ledger.verify()["valid"]
    with pytest.raises(ValueError, match="integrity"):
        ledger.receipts()


def test_append_only_triggers_and_v1_ledger_unaffected(world):
    environment = Environment.ephemeral("env:review", Signer.generate("autheo-test-authority"))
    try:
        ledger = DelegationLedger(environment, append_only=True)
        with closing(sqlite3.connect(environment.path)) as db:
            db.execute("INSERT INTO v2_revocations VALUES ('x', 'y', '{}')")
            db.commit()
            with pytest.raises(sqlite3.DatabaseError):
                db.execute("DELETE FROM v2_revocations")
        assert environment.verify_ledger()["valid"] and ledger.verify()["valid"]
    finally:
        environment.close()


def test_verifier_cli_bundle_chain_and_invocation(world, tmp_path, capsys):
    ledger, invoke = world["ledger"], world["invoke"]
    invocation = invoke(amount_minor=5)
    bundle = ledger.evaluate(invocation)["bundle"]
    (tmp_path / "bundle.json").write_text(json.dumps(bundle))
    (tmp_path / "inv.json").write_text(json.dumps(invocation))
    revocation = issue_revocation(ROOT.signer, world["chain"][0], revoked_at=world["now"])
    (tmp_path / "revocations.json").write_text(json.dumps({"schema_version": "autheo.revocation-list/v2",
                                                            "generated_at": world["now"], "records": [revocation]}))
    assert verifier_main(["bundle", str(tmp_path / "bundle.json"), "--root", ROOT.did,
                          "--environment-did", ledger.did]) == 0
    assert verifier_main(["bundle", str(tmp_path / "bundle.json"), "--root", STRANGER.did]) == 1
    assert verifier_main(["chain", str(tmp_path / "inv.json"), "--any-root", "--at", str(world["now"])]) == 0
    assert verifier_main(["chain", str(tmp_path / "bundle.json"), "--root", ROOT.did,
                          "--revocations", str(tmp_path / "revocations.json")]) == 1
    assert verifier_main(["invocation", str(tmp_path / "inv.json"), "--root", ROOT.did,
                          "--at", str(world["now"] + 1)]) == 0
    assert verifier_main(["invocation", str(tmp_path / "inv.json"), "--root", ROOT.did,
                          "--at", str(world["now"] + 3600)]) == 1
    assert verifier_main(["chain", str(tmp_path / "missing.json"), "--any-root"]) == 2
    capsys.readouterr()
