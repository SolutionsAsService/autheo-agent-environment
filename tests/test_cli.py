import json
import sqlite3
from pathlib import Path

import pytest

from autheo_agent_environment.audit import verify_archive
from autheo_agent_environment.canonical import digest
from autheo_agent_environment.cli import main
from autheo_agent_environment.models import Request
from autheo_agent_environment.signing import Signer, public_pem, read_public

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cli(tmp_path, capsys):
    state = tmp_path / "state"

    def run(*argv, code=0):
        result = main(["--state-dir", str(state), *argv])
        captured = capsys.readouterr()
        assert result == code, (captured.out, captured.err)
        text = captured.out if code == 0 or captured.out else captured.err
        return json.loads(text) if text.strip() else None

    run("init", "--environment", "env:research", "--environment", "env:review")
    return run, state, tmp_path


def test_end_to_end_cli_flow(cli):
    run, state, tmp = cli
    agent = Signer.generate("agent:cli")
    agent = Signer.for_agent(agent.issuer, agent.key)
    key_file = tmp / "agent.pem"
    key_file.write_text(public_pem(agent.public_key))
    info = run("info")
    assert info["executes_actions"] is False and info["kid"].startswith("local-")
    identity = run("identity", "issue", "--agent-id", agent.issuer, "--owner-id", "human:op",
                   "--environment", "env:research", "--environment", "env:review",
                   "--public-key-file", str(key_file))
    assert identity["custody"] == "agent_held"
    assert run("identity", "show", agent.issuer)["revoked"] is False
    mandate = run("mandate", "grant", "--agent-id", agent.issuer, "--environment", "env:research",
                  "--scope", "tool.invoke", "--scope", "environment.handoff", "--resource", "repo:jarvis",
                  "--tool", "git.status", "--destination", "env:review", "--per-action", "50", "--total", "60",
                  "--threshold", "40")
    mandate_id = mandate["mandate_id"]
    assert run("mandate", "list")["mandates"][0]["mandate_id"] == mandate_id

    def request_file(name, amount):
        body = Request(request_id=name, agent_id=agent.issuer, environment="env:research", mandate_id=mandate_id,
                       action="tool.invoke", resource="repo:jarvis", tool="git.status", amount_minor=amount)
        path = tmp / f"{name.replace(':', '_')}.jwt"
        path.write_text(agent.issue("request", agent.issuer, "env:research", body.model_dump()))
        return str(path)

    allowed = run("evaluate", "--request-token-file", request_file("req:1", 30))
    assert allowed["outcome"] == "allow"
    exhausted = run("evaluate", "--request-token-file", request_file("req:2", 31))
    assert exhausted["outcome"] == "block" and exhausted["reasons"] == ["total_budget_limit"]
    assert run("mandate", "show", mandate_id)["spent_minor"] == 30
    assert run("outcome", "--environment", "env:research", "--request-id", "req:1",
               "--status", "succeeded")["receipt"]["kind"] == "outcome_report"
    receipt_file = tmp / "receipt.jwt"
    receipt_file.write_text(allowed["receipt_token"])
    assert run("receipt", "verify", str(receipt_file))["in_ledger"]
    assert len(run("receipt", "list", "--environment", "env:research", "--limit", "2")["receipts"]) == 2

    handoff_file = tmp / "handoff.jwt"
    run("checkpoint", "--agent-id", agent.issuer, "--mandate-id", mandate_id, "--destination", "env:review",
        "--scope", "tool.invoke", "--task-id", "task:1", "--step", "inspected",
        "--artifact-sha256", digest({"x": 1}), "--output", str(handoff_file))
    assert run("handoff", "accept", "--token-file", str(handoff_file),
               "--allowed-scope", "tool.invoke")["receipt"]["kind"] == "handoff_import"
    assert run("handoff", "accept", "--token-file", str(handoff_file), "--allowed-scope", "tool.invoke",
               code=2)["error"] == "conflict"

    anchor = tmp / "anchor.json"
    head = run("ledger", "anchor", "--environment", "env:research", "--output", str(anchor))["head"]
    assert run("ledger", "verify", "--environment", "env:research", "--anchor", str(anchor))["valid"]
    archive = tmp / "archive.json"
    exported = run("ledger", "export", "--environment", "env:research", "--output", str(archive))
    assert exported["head"] == head
    config = json.loads((state / "config.json").read_text())
    summary = verify_archive(json.loads(archive.read_text()), read_public((state / "issuer-public.pem").read_text()),
                             config["issuer"], "env:research", head, kid=config["kid"])
    assert summary["external_checkpoint_matched"]

    run("mandate", "revoke", mandate_id)
    assert run("evaluate", "--request-token-file", request_file("req:3", 1))["reasons"] == ["revoked"]
    assert run("ledger", "verify", "--environment", "env:research", "--expected-head", head, code=1)["valid"] is False
    assert run("identity", "revoke", agent.issuer)["revoked"] is True


def test_cli_tamper_detection_exit_code(cli):
    run, state, _ = cli
    run("identity", "issue", "--agent-id", "agent:dev", "--owner-id", "human:op", "--environment",
        "env:research", "--generate-key")
    mandate = run("mandate", "grant", "--agent-id", "agent:dev", "--environment", "env:research", "--scope",
                  "compute.simulate", "--resource", "listing:one", "--per-action", "10", "--total", "10",
                  "--threshold", "10")
    result = run("evaluate", "--agent-id", "agent:dev", "--mandate-id", mandate["mandate_id"], "--action",
                 "compute.simulate", "--resource", "listing:one", "--amount", "5")
    assert result["request_proof"] == "service_held_key_local_dev"
    assert run("ledger", "verify", "--environment", "env:research")["valid"]
    ledger = state / "ledger-env_research.db"
    with sqlite3.connect(ledger) as db:
        db.execute("DROP TRIGGER events_append_only_update")
        db.execute("UPDATE events SET chain_hash=? WHERE sequence=2", ("e" * 64,))
    report = run("ledger", "verify", "--environment", "env:research", code=1)
    assert report["first_invalid_sequence"] == 2
    assert run("ledger", "anchor", "--environment", "env:research", "--output", str(state / "a.json"),
               code=1)["valid"] is False


def test_cli_errors_and_policy(cli, tmp_path):
    run, state, _ = cli
    assert run("init", code=2)["error"] == "exists"
    assert run("identity", "show", "agent:none", code=2)["error"] == "not_found"
    assert run("evaluate", "--agent-id", "agent:none", code=2)["error"] == "rejected"
    assert run("mandate", "grant", "--agent-id", "agent:none", "--environment", "env:research", "--scope",
               "tool.invoke", "--resource", "r", "--per-action", "1", "--total", "1", "--threshold", "2",
               code=2)["error"] in {"schema_validation_failed", "not_found"}
    assert run("policy", "show")["policy"]["policy_id"] == "policy:local-default"
    good = tmp_path / "p.yaml"
    good.write_text("policy_id: policy:x\n")
    assert run("policy", "validate", str(good))["valid"]
    bad = tmp_path / "bad.yaml"
    bad.write_text("policy_id: policy:x\nunknown: 1\n")
    assert run("policy", "validate", str(bad), code=2)["error"] == "schema_validation_failed"
    receipt = tmp_path / "r.jwt"
    receipt.write_text("garbage.token.value-long-enough")
    assert run("receipt", "verify", str(receipt), code=2)["error"] == "token_invalid"
    missing = main(["--state-dir", str(tmp_path / "nowhere"), "info"])
    assert missing == 2


def test_artifact_commands(cli, tmp_path):
    run, _, _ = cli
    assert run("schema", "check", str(ROOT / "schemas"))["up_to_date"]
    assert run("vectors", "check", str(ROOT / "tests" / "vectors" / "autheo-v1-vectors.json"))["up_to_date"]
    assert run("openapi", "check", str(ROOT / "docs" / "openapi.json"))["up_to_date"]
    run("schema", "export", str(tmp_path / "schemas"))
    assert run("schema", "check", str(tmp_path / "schemas"))["up_to_date"]
    (tmp_path / "schemas" / "receipt.v1.schema.json").write_text("{}")
    assert run("schema", "check", str(tmp_path / "schemas"), code=1)["stale"] == ["receipt.v1.schema.json"]
    run("vectors", "generate", str(tmp_path / "v.json"))
    run("openapi", "write", str(tmp_path / "o.json"))
    (tmp_path / "o.json").write_text("{}")
    assert run("openapi", "check", str(tmp_path / "o.json"), code=1)["up_to_date"] is False


def test_init_with_custom_policy_and_demo(tmp_path, capsys):
    policy = tmp_path / "policy.yaml"
    policy.write_text("policy_id: policy:custom\n")
    assert main(["--state-dir", str(tmp_path / "s"), "init", "--policy", str(policy)]) == 0
    capsys.readouterr()
    assert main(["--state-dir", str(tmp_path / "s"), "policy", "show"]) == 0
    assert json.loads(capsys.readouterr().out)["policy"]["policy_id"] == "policy:custom"
    assert main(["--state-dir", str(tmp_path / "s2"), "init", "--environment", "bad id"]) == 2
    assert main(["demo", "--output", str(tmp_path / "demo")]) == 0
    assert json.loads(capsys.readouterr().out)["decisions"] == ["allow", "escalate", "block"]
