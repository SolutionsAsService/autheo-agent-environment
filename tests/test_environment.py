import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import jwt
import pytest
from pydantic import ValidationError

from autheo_agent_environment.demo import run
from autheo_agent_environment.environment import Environment
from autheo_agent_environment.models import Checkpoint, Mandate, Passport, Request
from autheo_agent_environment.signing import Signer, digest, public_pem, verify


@pytest.fixture
def setup(tmp_path):
    authority = Signer.generate("issuer:demo")
    agent = Signer.generate("agent:one")
    passport = Passport(
        agent_id=agent.issuer,
        owner_id="owner:one",
        public_key=public_pem(agent.public_key),
        environments=["env:one", "env:two"],
    )
    mandate = Mandate(
        agent_id=agent.issuer,
        owner_id=passport.owner_id,
        environment="env:one",
        scopes=["compute.simulate", "marketplace.read", "environment.handoff"],
        resources=["listing:one"],
        destinations=["env:two"],
        per_action_minor=80,
        total_budget_minor=100,
        approval_threshold_minor=50,
    )
    pt = authority.issue(
        "passport", agent.issuer, "autheo-agent-environment", passport.model_dump(), ttl=3600
    )
    mt = authority.issue("mandate", agent.issuer, "env:one", mandate.model_dump(), ttl=3600)
    source = Environment(tmp_path / "source.db", "env:one", authority)
    destination = Environment(tmp_path / "destination.db", "env:two", authority)
    return dict(
        authority=authority,
        agent=agent,
        passport=pt,
        mandate=mt,
        source=source,
        destination=destination,
        policy=mandate,
        tmp_path=tmp_path,
    )


def request(s, name="req:one", amount=40, **changes):
    mandate_id = s["source"].owner_document(s["mandate"], "mandate", "env:one")["jti"]
    fields = dict(
        request_id=name,
        agent_id=s["agent"].issuer,
        environment="env:one",
        mandate_id=mandate_id,
        action="compute.simulate",
        resource="listing:one",
        amount_minor=amount,
    )
    fields.update(changes)
    return s["agent"].issue("request", s["agent"].issuer, "env:one", Request(**fields).model_dump())


def simulate(s, token):
    return s["source"].simulate(s["passport"], s["mandate"], token)


def resign(s, token, **claims):
    original = jwt.decode(token, options={"verify_signature": False})
    original.update(claims)
    return jwt.encode(
        original, s["authority"].key, algorithm="EdDSA", headers=jwt.get_unverified_header(token)
    )


def handoff(s, scopes=None):
    return s["source"].prepare_handoff(
        s["passport"],
        s["mandate"],
        "env:two",
        scopes or ["marketplace.read"],
        Checkpoint(task_id="task:one", step="inspected", artifact_sha256=digest({"demo": 1})),
    )


def test_three_outcomes_and_snapshot(setup):
    s = setup
    assert simulate(s, request(s))["decision"] == "allow"
    assert simulate(s, request(s, "req:review", 51))["decision"] == "escalate"
    assert simulate(s, request(s, "req:block", 101))["decision"] == "block"
    snapshot = s["source"].snapshot(s["passport"], s["mandate"])
    claims = verify(
        snapshot, "trust-snapshot", s["authority"].public_key, "issuer:demo", "autheo-mcp-readonly"
    )
    assert claims["body"]["mandate"]["spent_minor"] == 40
    assert claims["body"]["mandate"]["remaining_minor"] == 60
    assert claims["body"]["execution_authorized"] is False
    assert all(not receipt["executed"] for receipt in claims["body"]["receipts"])


def test_idempotency_and_conflicting_reuse(setup):
    s = setup
    token = request(s)
    first, replay = simulate(s, token), simulate(s, token)
    assert first["hash"] == replay["hash"] and replay["replayed"]
    assert s["source"].audit()["count"] == 1
    with pytest.raises(ValueError, match="Idempotency"):
        simulate(s, request(s, amount=41))


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"action": "chain.read"}, "scope_denied"),
        ({"resource": "listing:other"}, "resource_denied"),
        ({"amount_minor": 81}, "per_action_limit"),
    ],
)
def test_policy_denials(setup, changes, reason):
    fields = dict(amount=40)
    if "amount_minor" in changes:
        fields["amount"] = changes["amount_minor"]
        changes = {}
    result = simulate(setup, request(setup, **fields, **changes))
    assert result["decision"] == "block" and reason in result["reasons"]


@pytest.mark.parametrize("amount", [-1, 1.1, True, "1", 10**15 + 1])
def test_strict_money_types(setup, amount):
    with pytest.raises(ValidationError):
        request(setup, amount=amount)


def test_cumulative_budget(setup):
    s = setup
    simulate(s, request(s, "req:1", 40))
    simulate(s, request(s, "req:2", 50))
    result = simulate(s, request(s, "req:3", 20))
    assert result["decision"] == "block" and "total_budget_limit" in result["reasons"]


def test_concurrent_reservations_cannot_overspend(setup):
    s = setup
    policy = s["policy"].model_copy(update={"approval_threshold_minor": 80})
    s["mandate"] = s["authority"].issue("mandate", s["agent"].issuer, "env:one", policy.model_dump())
    tokens = [request(s, "req:a", 60), request(s, "req:b", 60)]
    with ThreadPoolExecutor(max_workers=2) as workers:
        decisions = list(workers.map(lambda t: simulate(s, t)["decision"], tokens))
    assert sorted(decisions) == ["allow", "block"]
    assert s["source"].audit()["count"] == 2


def test_revocation_denies_new_requests(setup):
    s = setup
    mandate_id = s["source"].owner_document(s["mandate"], "mandate", "env:one")["jti"]
    s["source"].revoke(mandate_id)
    assert simulate(s, request(s))["reasons"] == ["revoked"]
    with pytest.raises(ValueError, match="Revoked"):
        handoff(s)


@pytest.mark.parametrize("claim,value", [("aud", "env:other"), ("iss", "attacker"), ("sub", "agent:other")])
def test_signed_but_wrong_context_rejected(setup, claim, value):
    s = setup
    s["mandate"] = resign(s, s["mandate"], **{claim: value})
    with pytest.raises((ValueError, jwt.InvalidTokenError)):
        simulate(s, s["agent"].issue("request", s["agent"].issuer, "env:one", {}))


def test_expiry_and_future_validity(setup):
    s = setup
    token = request(s)
    now = int(time.time())
    for claims in [
        dict(iat=now - 400, nbf=now - 400, exp=now - 1),
        dict(iat=now + 100, nbf=now + 100, exp=now + 200),
    ]:
        expired = resign(s, s["mandate"], **claims)
        with pytest.raises(jwt.InvalidTokenError):
            s["source"].simulate(s["passport"], expired, token)


def test_foreign_key_cannot_impersonate_agent(setup):
    s = setup
    other = Signer.generate(s["agent"].issuer)
    body = jwt.decode(request(s), options={"verify_signature": False})["body"]
    forged = other.issue("request", s["agent"].issuer, "env:one", body)
    with pytest.raises(jwt.InvalidSignatureError):
        simulate(s, forged)


def test_token_algorithm_and_type_confusion(setup):
    s = setup
    token = s["authority"].issue("trust-snapshot", s["agent"].issuer, "autheo-agent-environment", {})
    with pytest.raises(ValueError, match="type"):
        s["source"].credentials(token, s["mandate"])
    original = jwt.decode(s["passport"], options={"verify_signature": False})
    forged = jwt.encode(
        original, "a" * 32, algorithm="HS256", headers={"typ": "autheo-passport+jwt", "kid": "demo-v1"}
    )
    with pytest.raises(jwt.InvalidAlgorithmError):
        s["source"].credentials(forged, s["mandate"])


def test_handoff_no_budget_no_execution_and_replay(setup):
    s = setup
    token = handoff(s)
    result = s["destination"].accept_handoff(token, s["passport"], s["mandate"], ["marketplace.read"])
    assert result["decision"] == "checkpoint_only" and result["amount_minor"] == 0
    assert result["executed"] is False
    assert "fresh_destination_mandate_required" in result["reasons"]
    with pytest.raises(ValueError, match="replay"):
        s["destination"].accept_handoff(token, s["passport"], s["mandate"], ["marketplace.read"])


def test_handoff_cannot_expand_scope(setup):
    s = setup
    with pytest.raises(ValueError, match="scope"):
        handoff(s, ["chain.read"])
    token = handoff(s)
    with pytest.raises(ValueError, match="policy"):
        s["destination"].accept_handoff(token, s["passport"], s["mandate"], [])
    with pytest.raises(jwt.InvalidAudienceError):
        s["source"].accept_handoff(token, s["passport"], s["mandate"], ["marketplace.read"])


def test_handoff_expired_and_wrong_passport(setup):
    s = setup
    token = handoff(s)
    now = int(time.time())
    with pytest.raises(jwt.ExpiredSignatureError):
        s["destination"].accept_handoff(
            resign(s, token, iat=now - 200, nbf=now - 200, exp=now - 1),
            s["passport"],
            s["mandate"],
            ["marketplace.read"],
        )
    changed_passport = resign(s, s["passport"], jti="different-passport")
    with pytest.raises(ValueError, match="mismatch"):
        s["destination"].accept_handoff(token, changed_passport, s["mandate"], ["marketplace.read"])


def test_handoff_rejects_secret_fields():
    with pytest.raises(ValidationError):
        Checkpoint(task_id="task:one", step="planned", artifact_sha256="0" * 64, api_key="must-not-travel")


def test_audit_detects_edit_and_missing_anchored_tail(setup):
    s = setup
    simulate(s, request(s, "req:1"))
    simulate(s, request(s, "req:2", 20))
    head = s["source"].audit()["head"]
    with sqlite3.connect(s["source"].path) as db:
        db.execute("DELETE FROM events WHERE sequence=2")
    with pytest.raises(ValueError, match="checkpoint"):
        s["source"].audit(expected_head=head)
    with sqlite3.connect(s["source"].path) as db:
        db.execute("UPDATE events SET chain_hash=?", ("0" * 64,))
    with pytest.raises(ValueError, match="integrity"):
        s["source"].audit()
    with pytest.raises(ValueError, match="integrity"):
        simulate(s, request(s, "req:3", 1))


def test_wrong_database_identity_rejected(setup):
    with pytest.raises(ValueError, match="different"):
        Environment(setup["source"].path, "env:wrong", setup["authority"])


def test_export_contains_no_private_keys_or_authorizing_tokens(setup):
    s = setup
    directory = s["tmp_path"] / "export"
    s["source"].export_snapshot(directory, s["passport"], s["mandate"])
    assert {p.name for p in directory.iterdir()} == {
        "trust-snapshot.jwt",
        "issuer-public.pem",
        "mcp-environment.json",
    }
    all_output = "".join(p.read_text() for p in directory.iterdir())
    assert "PRIVATE KEY" not in all_output
    assert s["passport"] not in all_output and s["mandate"] not in all_output


def test_demo_expected_story(tmp_path):
    result = run(tmp_path / "demo")
    assert result["decisions"] == ["allow", "escalate", "block"]
    assert result["handoff"]["decision"] == "checkpoint_only"
    assert json.loads((tmp_path / "demo" / "demo-report.json").read_text())["prototype"]


def test_offline_archive_verification(setup):
    from autheo_agent_environment.audit import verify_archive

    s = setup
    simulate(s, request(s))
    output = s["tmp_path"] / "receipts.json"
    s["source"].export_audit(output)
    archive = json.loads(output.read_text())
    assert verify_archive(
        archive, s["authority"].public_key, "issuer:demo", "env:one", s["source"].audit()["head"]
    )["external_checkpoint_matched"]
    with pytest.raises(jwt.InvalidSignatureError):
        verify_archive(archive, Signer.generate("wrong").public_key, "issuer:demo", "env:one")
    archive["receipts"].clear()
    with pytest.raises(ValueError, match="checkpoint"):
        verify_archive(
            archive, s["authority"].public_key, "issuer:demo", "env:one", s["source"].audit()["head"]
        )
