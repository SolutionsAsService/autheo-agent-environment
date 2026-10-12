import json
import sqlite3

import jwt
import pytest

from autheo_agent_environment.audit import verify_archive
from autheo_agent_environment.environment import Environment
from autheo_agent_environment.errors import ConflictError, NotFoundError
from autheo_agent_environment.ledger import anchor_record, read_anchor, verify_database
from autheo_agent_environment.models import Mandate, OutcomeReport, Passport, ReceiptBody, Request
from autheo_agent_environment.policy import parse_policy
from autheo_agent_environment.signing import Signer, public_pem


@pytest.fixture
def world(tmp_path):
    authority = Signer.generate("issuer:demo")
    agent = Signer.for_agent("agent:one", Signer.generate("agent:one").key)
    passport = Passport(agent_id=agent.issuer, owner_id="owner:one", public_key=public_pem(agent.public_key),
                        environments=["env:one"])
    mandate = Mandate(agent_id=agent.issuer, owner_id="owner:one", environment="env:one",
                      scopes=["tool.invoke", "compute.simulate"], resources=["repo:one"], tools=["git.status"],
                      per_action_minor=50, total_budget_minor=100, approval_threshold_minor=50)
    policy = parse_policy({"policy_id": "policy:test",
                           "budgets": [{"id": "hourly", "limit_minor": 60, "window_seconds": 3600}]})
    environment = Environment(tmp_path / "ledger.db", "env:one", authority, policy, append_only=True)
    pt = authority.issue("passport", agent.issuer, "autheo-agent-environment", passport.model_dump(), ttl=3600)
    mt = authority.issue("mandate", agent.issuer, "env:one", mandate.model_dump(), ttl=3600)
    mandate_id = environment.owner_document(mt, "mandate", "env:one")["jti"]

    def request(name, amount=10, signer=agent, **changes):
        fields = dict(request_id=name, agent_id=agent.issuer, environment="env:one", mandate_id=mandate_id,
                      action="tool.invoke", resource="repo:one", tool="git.status", amount_minor=amount)
        fields.update(changes)
        return signer.issue("request", agent.issuer, "env:one", Request(**fields).model_dump())

    def evaluate(name, amount=10, **changes):
        return environment.evaluate(pt, mt, request(name, amount, **changes))

    return dict(authority=authority, agent=agent, env=environment, pt=pt, mt=mt, mandate_id=mandate_id,
                request=request, evaluate=evaluate, path=tmp_path / "ledger.db", tmp=tmp_path)


def verify(world, **kwargs):
    a = world["authority"]
    return verify_database(world["path"], a.public_key, a.issuer, "env:one", a.kid, **kwargs)


def test_v1_receipt_bodies_validate_and_carry_policy(world):
    result = world["evaluate"]("req:1")
    receipt = result["receipt"]
    assert ReceiptBody.model_validate({k: v for k, v in receipt.items() if k != "hash"})
    assert receipt["schema_version"] == "autheo.receipt/v1" and receipt["policy_id"] == "policy:test"
    assert receipt["tool"] == "git.status" and isinstance(receipt["recorded_at"], int)
    assert result["decision"].decision == "allow"


def test_policy_budget_exhaustion_through_environment(world):
    assert world["evaluate"]("req:1", 40)["receipt"]["decision"] == "allow"
    second = world["evaluate"]("req:2", 30)
    assert second["receipt"]["decision"] == "block"
    assert second["receipt"]["reasons"] == ["budget_exhausted:hourly"]
    assert world["env"].spent(world["mandate_id"]) == 40


def test_agent_kid_is_key_fingerprint_and_foreign_kid_rejected(world):
    agent = world["agent"]
    legacy = Signer(agent.issuer, agent.key)  # 0.1 kid "demo-v1" still accepted
    assert world["env"].evaluate(world["pt"], world["mt"], world["request"]("req:legacy", signer=legacy))
    odd = Signer(agent.issuer, agent.key, "some-other-kid")
    with pytest.raises(ValueError, match="key identifier"):
        world["env"].evaluate(world["pt"], world["mt"], world["request"]("req:odd", signer=odd))


def test_signature_failure_from_foreign_key(world):
    stranger = Signer.for_agent("agent:one", Signer.generate("x").key)
    token = world["request"]("req:forged", signer=stranger)
    with pytest.raises(ValueError):  # foreign fingerprint kid fails first
        world["env"].evaluate(world["pt"], world["mt"], token)
    impostor = Signer(stranger.issuer, stranger.key, world["agent"].kid)
    with pytest.raises(jwt.InvalidSignatureError):
        world["env"].evaluate(world["pt"], world["mt"], world["request"]("req:forged2", signer=impostor))
    assert verify(world)["count"] == 0


def test_revocation_is_recorded_and_blocks(world):
    receipt = world["env"].revoke(world["mandate_id"], agent_id="agent:one", reason="owner_requested")
    assert receipt["kind"] == "revocation" and receipt["decision"] == "revoked"
    assert world["env"].revoke(world["mandate_id"], agent_id="agent:one")["replayed"]
    blocked = world["evaluate"]("req:after")
    assert blocked["receipt"]["reasons"] == ["revoked"]


def test_outcome_reports(world):
    world["evaluate"]("req:ok", 10)
    env = world["env"]
    with pytest.raises(NotFoundError):
        env.record_outcome("req:missing", "succeeded")
    report = env.record_outcome("req:ok", "succeeded")
    assert report["kind"] == "outcome_report" and report["executed"] is False
    assert report["reported_by"] == "operator_api" and report["reference"] == "req:ok"
    assert report["reasons"] == ["executor_reported_succeeded", "not_independently_verified"]
    assert env.record_outcome("req:ok", "succeeded")["replayed"]
    with pytest.raises(ConflictError):
        env.record_outcome("req:ok", "failed")


def test_outcome_rejected_for_blocked_and_signed_reports(world):
    env, agent = world["env"], world["agent"]
    world["evaluate"]("req:blocked", 10, resource="repo:other")
    with pytest.raises(ValueError, match="allowed"):
        env.record_outcome("req:blocked", "succeeded")
    world["evaluate"]("req:signed", 10)
    body = OutcomeReport(request_id="req:signed", agent_id=agent.issuer, environment="env:one",
                         status="failed").model_dump()
    token = agent.issue("outcome", agent.issuer, "env:one", body)
    with pytest.raises(ValueError, match="public key"):
        env.record_outcome("req:signed", "failed", report_token=token)
    mismatch = agent.issue("outcome", agent.issuer, "env:one", {**body, "status": "succeeded"})
    with pytest.raises(ValueError, match="does not match"):
        env.record_outcome("req:signed", "failed", report_token=mismatch,
                           agent_public_key=public_pem(agent.public_key))
    forged = Signer(agent.issuer, Signer.generate("x").key, agent.kid).issue("outcome", agent.issuer,
                                                                             "env:one", body)
    with pytest.raises(jwt.InvalidSignatureError):
        env.record_outcome("req:signed", "failed", report_token=forged,
                           agent_public_key=public_pem(agent.public_key))
    signed = env.record_outcome("req:signed", "failed", report_token=token,
                                agent_public_key=public_pem(agent.public_key))
    assert signed["reported_by"] == "agent_signed" and signed["reported_status"] == "failed"


def test_append_only_triggers_reject_edits(world):
    world["evaluate"]("req:1")
    world["env"].revoke("some-jti")
    with sqlite3.connect(world["path"]) as db:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("UPDATE events SET token='x'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM events")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            db.execute("DELETE FROM revoked")
    report = verify(world)
    assert report["valid"] and report["append_only_triggers"] and report["count"] == 1
    assert report["immutable"] is False and report["externally_anchored"] is False


def _drop_triggers(path):
    with sqlite3.connect(path) as db:
        for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
            db.execute(f"DROP TRIGGER {name}")


def test_tamper_detection_localises_the_bad_row(world):
    for index in range(1, 5):
        world["evaluate"](f"req:{index}", 5)
    head = verify(world)["head"]
    _drop_triggers(world["path"])
    with sqlite3.connect(world["path"]) as db:
        token = db.execute("SELECT token FROM events WHERE sequence=2").fetchone()[0]
        header, payload, signature = token.split(".")
        forged = ".".join([header, payload[:-2] + ("A" if payload[-2] != "A" else "B") + payload[-1], signature])
        db.execute("UPDATE events SET token=? WHERE sequence=2", (forged,))
    report = verify(world)
    assert not report["valid"] and report["first_invalid_sequence"] == 2
    assert not report["append_only_triggers"]
    problems = {p["problem"] for p in report["problems"]}
    assert any(p.startswith("signature_or_claims_invalid") for p in problems)
    assert "chain_hash_mismatch" in problems
    with pytest.raises((ValueError, jwt.InvalidTokenError)):
        world["env"].audit()
    assert verify(world, expected_head=head)["expected_head_matched"] is False


def test_forged_chain_hash_and_deleted_row(world):
    for index in range(1, 4):
        world["evaluate"](f"req:{index}", 5)
    _drop_triggers(world["path"])
    with sqlite3.connect(world["path"]) as db:
        db.execute("UPDATE events SET chain_hash=? WHERE sequence=3", ("f" * 64,))
    report = verify(world)
    assert report["first_invalid_sequence"] == 3 and report["problems"][0]["problem"] == "chain_hash_mismatch"
    with sqlite3.connect(world["path"]) as db:
        db.execute("DELETE FROM events WHERE sequence=2")
    gaps = {p["problem"] for p in verify(world)["problems"]}
    assert {"sequence_gap_or_reorder", "previous_hash_mismatch"} <= gaps


def test_truncation_needs_an_external_anchor(world, tmp_path):
    for index in range(1, 4):
        world["evaluate"](f"req:{index}", 5)
    anchor_file = tmp_path / "anchor.json"
    anchor_file.write_text(json.dumps(anchor_record(verify(world))))
    _drop_triggers(world["path"])
    with sqlite3.connect(world["path"]) as db:
        db.execute("DELETE FROM events WHERE sequence=3")
    assert verify(world)["valid"]  # a clean prefix is indistinguishable without an anchor
    anchored = verify(world, expected_head=read_anchor(anchor_file))
    assert not anchored["valid"] and anchored["problems"][-1]["problem"] == "head_differs_from_anchor"
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(ValueError):
        read_anchor(bad)


def test_wrong_trust_anchor_and_missing_file(world, tmp_path):
    world["evaluate"]("req:1")
    other = Signer.generate("issuer:demo")
    report = verify_database(world["path"], other.public_key, "issuer:demo", "env:one", "demo-v1")
    assert not report["valid"] and report["problems"][0]["problem"] == "ledger_identity_mismatch"
    with pytest.raises(FileNotFoundError):
        verify_database(tmp_path / "missing.db", other.public_key, "issuer:demo", "env:one", "demo-v1")
    assert not (tmp_path / "missing.db").exists()


def test_receipt_verification_and_archive_export(world, tmp_path):
    result = world["evaluate"]("req:1")
    stored = world["env"].receipt("req:1")
    assert stored["receipt"]["hash"] == result["receipt"]["hash"]
    check = world["env"].verify_receipt(stored["token"])
    assert check["in_ledger"] and check["sequence"] == 1 and check["actual_action_proven"] is False
    outsider = world["authority"].issue("receipt", "agent:one", "env:one", {"sequence": 99}, ttl=60)
    assert world["env"].verify_receipt(outsider)["in_ledger"] is False
    with pytest.raises(jwt.InvalidSignatureError):
        world["env"].verify_receipt(Signer.generate("issuer:demo").issue("receipt", "a", "env:one", {}, ttl=60))
    archive_path = tmp_path / "archive.json"
    world["env"].revoke(world["mandate_id"], agent_id="agent:one")
    world["env"].export_audit(archive_path)
    a = world["authority"]
    summary = verify_archive(json.loads(archive_path.read_text()), a.public_key, a.issuer, "env:one",
                             world["env"].audit()["head"], kid=a.kid)
    assert summary["count"] == 2 and summary["external_checkpoint_matched"]
    assert len(world["env"].receipts(limit=1)) == 1


def test_ephemeral_environment_cleans_up():
    environment = Environment.ephemeral("env:tmp", Signer.generate("issuer:demo"))
    path = environment.path
    assert path.exists()
    environment.close()
    environment.close()
    assert not path.exists()
