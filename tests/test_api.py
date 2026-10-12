import json
import threading
from http.client import HTTPConnection
from pathlib import Path

import pytest

from autheo_agent_environment.api import ApiRouter, create_api_server, is_loopback
from autheo_agent_environment.canonical import digest
from autheo_agent_environment.models import OutcomeReport, Request
from autheo_agent_environment.openapi import render as render_openapi
from autheo_agent_environment.service import TrustService
from autheo_agent_environment.signing import Signer, public_pem

ROOT = Path(__file__).resolve().parents[1]
POLICY = """
policy_id: policy:api-test
tools:
  deny: ["shell.*"]
budgets:
  - id: daily
    limit_minor: 70
    window_seconds: 86400
escalations:
  - id: deploys
    tools: ["deploy.*"]
"""


class Client:
    def __init__(self, server, token):
        self.port, self.token = server.server_port, token

    def call(self, method, path, payload=None, *, token=True, headers=None, raw=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        sent = {"Content-Type": "application/json"}
        if token:
            sent["Authorization"] = f"Bearer {self.token if token is True else token}"
        sent.update(headers or {})
        body = raw if raw is not None else (json.dumps(payload) if payload is not None else None)
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        data = json.loads(response.read() or b"{}")
        status, response_headers = response.status, response.headers
        connection.close()
        return status, data, response_headers

    def ok(self, method, path, payload=None):
        status, data, _ = self.call(method, path, payload)
        assert status == 200, data
        return data


@pytest.fixture
def api():
    service = TrustService.ephemeral(policy_text=POLICY)
    server = create_api_server(service, service.state.api_token, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    agent = Signer.generate("agent:jarvis-1")
    agent = Signer.for_agent(agent.issuer, agent.key)
    client = Client(server, service.state.api_token)
    yield dict(client=client, service=service, agent=agent, server=server)
    server.shutdown()
    server.server_close()
    service.close()
    thread.join(timeout=2)


def enroll(api, tools=("git.status", "shell.exec", "deploy.prod"), total=100, ttl=3600):
    client, agent = api["client"], api["agent"]
    identity = client.ok("POST", "/v1/identities", {
        "agent_id": agent.issuer, "owner_id": "human:owner", "environments": ["env:research", "env:review"],
        "public_key": public_pem(agent.public_key),
    })
    assert identity["custody"] == "agent_held" and identity["key_fingerprint"] == agent.kid
    mandate = client.ok("POST", "/v1/mandates", {
        "agent_id": agent.issuer, "environment": "env:research",
        "scopes": ["tool.invoke", "environment.handoff"], "resources": ["repo:jarvis"], "tools": list(tools),
        "destinations": ["env:review"], "per_action_minor": 50, "total_budget_minor": total,
        "approval_threshold_minor": 40, "ttl_seconds": ttl,
    })
    return identity, mandate


def signed_request(api, mandate_id, name, tool="git.status", amount=10, signer=None):
    request = Request(request_id=name, agent_id=api["agent"].issuer, environment="env:research",
                      mandate_id=mandate_id, action="tool.invoke", resource="repo:jarvis", tool=tool,
                      amount_minor=amount)
    return (signer or api["agent"]).issue("request", api["agent"].issuer, "env:research", request.model_dump())


def evaluate(api, mandate_id, name, **kwargs):
    return api["client"].call("POST", "/v1/evaluate",
                              {"request_token": signed_request(api, mandate_id, name, **kwargs)})


def test_public_routes_and_auth(api):
    client = api["client"]
    status, health, headers = client.call("GET", "/v1/health", token=False)
    assert status == 200 and health["executes_actions"] is False
    assert headers["Cache-Control"] == "no-store" and headers.get("Access-Control-Allow-Origin") is None
    assert client.call("GET", "/v1/openapi.json", token=False)[1]["openapi"] == "3.1.0"
    assert "receipt" in client.call("GET", "/v1/schemas", token=False)[1]["schemas"]
    assert client.call("GET", "/v1/schemas/receipt", token=False)[1]["$id"] == "urn:autheo:schema:receipt:v1"
    assert client.call("GET", "/v1/schemas/nope", token=False)[0] == 404
    assert client.call("GET", "/v1/info", token=False)[0] == 401
    assert client.call("GET", "/v1/info", token="wrong-token-value-123")[0] == 401
    info = client.ok("GET", "/v1/info")
    assert info["executes_actions"] is False and info["production_did_wallet_or_payments"] is False
    assert client.ok("GET", "/v1/policy")["policy"]["policy_id"] == "policy:api-test"
    assert client.call("GET", "/elsewhere")[0] == 404
    assert client.call("DELETE", "/v1/info")[0] == 405


def test_host_origin_and_body_guards(api):
    client = api["client"]
    assert client.call("GET", "/v1/info", headers={"Host": "evil.example:80"})[0] == 421
    assert client.call("GET", "/v1/info", headers={"Host": f"localhost:{client.port}"})[0] == 200
    assert client.call("GET", "/v1/info", headers={"Origin": "https://evil.example"})[0] == 403
    assert client.call("POST", "/v1/identities", raw="x", headers={"Content-Type": "text/plain"})[0] == 415
    assert client.call("POST", "/v1/identities", raw="{not json")[0] == 400
    assert client.call("POST", "/v1/identities", raw="[]")[0] == 400
    assert client.call("POST", "/v1/identities", raw="{" + " " * 70000 + "}")[0] == 413
    status, data, _ = client.call("POST", "/v1/identities", {"agent_id": "agent:x", "surprise": 1})
    assert status == 400 and data["error"] == "schema_validation_failed" and "surprise" in data["detail"]


def test_non_loopback_bind_refused():
    assert is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost")
    assert not is_loopback("0.0.0.0") and not is_loopback("example.com")
    service = TrustService.ephemeral()
    try:
        with pytest.raises(ValueError, match="non-loopback"):
            create_api_server(service, service.state.api_token, host="0.0.0.0", port=0)
        with pytest.raises(ValueError, match="short"):
            ApiRouter(service, "short")
    finally:
        service.close()


def test_full_flow_allow_policy_deny_escalate_budget_and_outcome(api):
    client = api["client"]
    _, mandate = enroll(api)
    mandate_id = mandate["mandate_id"]
    assert mandate["receipt"]["kind"] == "mandate_grant"

    status, allowed, _ = evaluate(api, mandate_id, "req:1", amount=30)
    assert status == 200 and allowed["outcome"] == "allow" and allowed["executed"] is False
    assert allowed["decision"]["policy_id"] == "policy:api-test"
    assert allowed["request_proof"] == "agent_signed_request" and allowed["receipt_token"]
    assert any(c["check"] == "policy.budget:daily" for c in allowed["decision"]["explanation"])

    assert evaluate(api, mandate_id, "req:shell", tool="shell.exec")[1]["reasons"] == ["policy_tool_denied"]
    assert evaluate(api, mandate_id, "req:deploy", tool="deploy.prod")[1]["reasons"] == [
        "policy_escalation:deploys"]
    assert evaluate(api, mandate_id, "req:2", amount=30)[1]["outcome"] == "allow"
    exhausted = evaluate(api, mandate_id, "req:3", amount=20)[1]
    assert exhausted["outcome"] == "block" and exhausted["reasons"] == ["budget_exhausted:daily"]

    status_view = client.ok("GET", f"/v1/mandates/{mandate_id}")
    assert status_view["spent_minor"] == 60 and status_view["remaining_minor"] == 40
    assert status_view["revoked"] is False

    replay = evaluate(api, mandate_id, "req:1", amount=30)[1]
    assert replay["replayed"] and replay["decision"] is None
    status, conflict, _ = evaluate(api, mandate_id, "req:1", amount=31)
    assert status == 409 and conflict["error"] == "conflict"

    outcome = client.ok("POST", "/v1/receipts/outcome", {"environment": "env:research", "request_id": "req:1",
                                                          "status": "succeeded"})
    assert outcome["receipt"]["reported_by"] == "operator_api"
    report = OutcomeReport(request_id="req:2", agent_id=api["agent"].issuer, environment="env:research",
                           status="failed", detail_sha256=digest({"exit": 1})).model_dump()
    signed = client.ok("POST", "/v1/receipts/outcome", {
        "environment": "env:research", "request_id": "req:2", "status": "failed",
        "detail_sha256": digest({"exit": 1}),
        "report_token": api["agent"].issue("outcome", api["agent"].issuer, "env:research", report)})
    assert signed["receipt"]["reported_by"] == "agent_signed"
    status, data, _ = client.call("POST", "/v1/receipts/outcome", {"environment": "env:research",
                                                                    "request_id": "req:shell",
                                                                    "status": "succeeded"})
    assert status == 400 and "allowed" in data["detail"]
    assert client.call("POST", "/v1/receipts/outcome", {"environment": "env:research", "request_id": "req:none",
                                                         "status": "succeeded"})[0] == 404


def test_revoked_mandate_and_identity(api):
    client = api["client"]
    _, mandate = enroll(api)
    mandate_id = mandate["mandate_id"]
    revoked = client.ok("POST", f"/v1/mandates/{mandate_id}/revoke", {"reason": "owner_requested"})
    assert revoked["receipt"]["kind"] == "revocation" and revoked["receipt"]["reasons"] == ["owner_requested"]
    blocked = evaluate(api, mandate_id, "req:after")[1]
    assert blocked["outcome"] == "block" and blocked["reasons"] == ["revoked"]
    assert client.ok("GET", f"/v1/mandates/{mandate_id}")["revoked"] is True
    assert client.call("POST", "/v1/mandates/nope/revoke", {})[0] == 404

    _, second = enroll(api)
    client.ok("POST", f"/v1/identities/{api['agent'].issuer}/revoke", {})
    assert client.ok("GET", f"/v1/identities/{api['agent'].issuer}")["revoked"] is True
    assert evaluate(api, second["mandate_id"], "req:id-revoked")[1]["reasons"] == ["revoked"]
    status, data, _ = client.call("POST", "/v1/mandates", {
        "agent_id": api["agent"].issuer, "environment": "env:research", "scopes": ["tool.invoke"],
        "resources": ["repo:jarvis"], "per_action_minor": 1, "total_budget_minor": 1,
        "approval_threshold_minor": 1})
    assert status == 400 and "revoked" in data["detail"]
    status, _, _ = client.call("POST", "/v1/identities", {
        "agent_id": api["agent"].issuer, "owner_id": "human:owner", "environments": ["env:research"],
        "public_key": public_pem(api["agent"].public_key)})
    assert status == 409


def test_signature_failures_and_identity_conflicts(api):
    client = api["client"]
    _, mandate = enroll(api)
    impostor = Signer(api["agent"].issuer, Signer.generate("x").key, api["agent"].kid)
    status, data, _ = evaluate(api, mandate["mandate_id"], "req:forged", signer=impostor)
    assert status == 400 and data["error"] == "signature_invalid"
    status, data, _ = client.call("POST", "/v1/evaluate", {"request_token": "not-a-jwt-but-long-enough"})
    assert status == 400 and data["error"] == "token_invalid"
    assert client.call("POST", "/v1/evaluate", {})[0] == 400
    unsigned = {"request": {"agent_id": api["agent"].issuer, "mandate_id": mandate["mandate_id"],
                            "action": "tool.invoke", "resource": "repo:jarvis", "tool": "git.status"}}
    status, data, _ = client.call("POST", "/v1/evaluate", unsigned)
    assert status == 400 and "service-held key" in data["detail"]
    other = Signer.generate("k")
    status, _, _ = client.call("POST", "/v1/identities", {
        "agent_id": api["agent"].issuer, "owner_id": "human:owner", "environments": ["env:research"],
        "public_key": public_pem(other.public_key)})
    assert status == 409
    assert client.call("POST", "/v1/identities", {
        "agent_id": "agent:x", "owner_id": "human:o", "environments": ["env:research"]})[0] == 400
    assert client.call("POST", "/v1/identities", {
        "agent_id": "agent:x", "owner_id": "human:o", "environments": ["env:unknown"],
        "generate_key": True})[0] == 404
    assert client.call("GET", "/v1/identities/agent:none")[0] == 404
    assert client.call("GET", "/v1/mandates/none")[0] == 404


def test_service_held_key_flow(api):
    client = api["client"]
    client.ok("POST", "/v1/identities", {"agent_id": "agent:dev", "owner_id": "human:o",
                                         "environments": ["env:research"], "generate_key": True})
    again = client.ok("POST", "/v1/identities", {"agent_id": "agent:dev", "owner_id": "human:o",
                                                 "environments": ["env:research"], "generate_key": True})
    assert again["custody"] == "local_dev_custody"
    mandate = client.ok("POST", "/v1/mandates", {
        "agent_id": "agent:dev", "environment": "env:research", "scopes": ["compute.simulate"],
        "resources": ["listing:one"], "per_action_minor": 10, "total_budget_minor": 10,
        "approval_threshold_minor": 10})
    result = client.ok("POST", "/v1/evaluate", {"request": {
        "agent_id": "agent:dev", "mandate_id": mandate["mandate_id"], "action": "compute.simulate",
        "resource": "listing:one", "amount_minor": 10}})
    assert result["outcome"] == "allow" and result["request_proof"] == "service_held_key_local_dev"
    status, _, _ = client.call("POST", "/v1/evaluate", {"request": {
        "agent_id": "agent:other", "mandate_id": mandate["mandate_id"], "action": "compute.simulate",
        "resource": "listing:one"}})
    assert status == 400


def test_receipt_and_ledger_verification(api):
    client = api["client"]
    _, mandate = enroll(api)
    result = evaluate(api, mandate["mandate_id"], "req:1")[1]
    check = client.ok("POST", "/v1/receipts/verify", {"token": result["receipt_token"]})
    assert check["signature_valid"] and check["in_ledger"] and check["actual_action_proven"] is False
    header, payload, signature = result["receipt_token"].split(".")
    tampered = ".".join([header, payload, signature[:-4] + ("AAAA" if signature[-4:] != "AAAA" else "BBBB")])
    status, data, _ = client.call("POST", "/v1/receipts/verify", {"token": tampered})
    assert status == 400 and data["error"] in {"signature_invalid", "token_invalid"}
    report = client.ok("GET", "/v1/ledger/verify?environment=env:research")
    assert report["valid"] and report["append_only_triggers"] and report["count"] == 3
    anchored = client.ok("POST", "/v1/ledger/verify", {"environment": "env:research",
                                                       "expected_head": "0" * 64})
    assert anchored["valid"] is False and anchored["expected_head_matched"] is False
    assert client.ok("GET", f"/v1/ledger/verify?environment=env:research&expected_head={report['head']}")["valid"]
    listing = client.ok("GET", "/v1/ledger/receipts?environment=env:research&limit=2")
    assert len(listing["receipts"]) == 2 and listing["count"] == 3
    assert client.call("GET", "/v1/ledger/receipts?environment=env:research&limit=0")[0] == 400
    assert client.call("GET", "/v1/ledger/receipts?environment=env:research&limit=x")[0] == 400
    assert client.call("GET", "/v1/ledger/verify?environment=env:nope")[0] == 404
    assert client.call("GET", "/v1/ledger/verify?environment=env:review")[0] == 200


def test_checkpoint_handoff_and_replay(api):
    client = api["client"]
    _, mandate = enroll(api)
    exported = client.ok("POST", "/v1/checkpoints", {
        "agent_id": api["agent"].issuer, "mandate_id": mandate["mandate_id"], "destination": "env:review",
        "scopes": ["tool.invoke"],
        "checkpoint": {"task_id": "task:1", "step": "inspected", "artifact_sha256": digest({"a": 1})}})
    assert exported["budget_transferred_minor"] == 0 and exported["receipt"]["kind"] == "handoff_export"
    accepted = client.ok("POST", "/v1/handoffs/accept", {"handoff_token": exported["handoff_token"],
                                                         "allowed_scopes": ["tool.invoke"]})
    assert accepted["receipt"]["kind"] == "handoff_import" and accepted["activation_requires_new_mandate"]
    status, data, _ = client.call("POST", "/v1/handoffs/accept", {"handoff_token": exported["handoff_token"],
                                                                  "allowed_scopes": ["tool.invoke"]})
    assert status == 409
    status, _, _ = client.call("POST", "/v1/checkpoints", {
        "agent_id": api["agent"].issuer, "mandate_id": mandate["mandate_id"], "destination": "env:review",
        "scopes": ["file.write"],
        "checkpoint": {"task_id": "task:1", "step": "inspected", "artifact_sha256": digest({"a": 1})}})
    assert status == 400
    status, _, _ = client.call("POST", "/v1/checkpoints", {
        "agent_id": "agent:other", "mandate_id": mandate["mandate_id"], "destination": "env:review",
        "scopes": ["tool.invoke"],
        "checkpoint": {"task_id": "task:1", "step": "inspected", "artifact_sha256": digest({"a": 1})}})
    assert status == 400


def test_expired_mandate_rejected(api, monkeypatch):
    import time as real_time

    _, mandate = enroll(api, ttl=10)
    token = signed_request(api, mandate["mandate_id"], "req:late")
    later = real_time.time() + 30
    monkeypatch.setattr("autheo_agent_environment.signing.time.time", lambda: later)
    status, data, _ = api["client"].call("POST", "/v1/evaluate", {"request_token": token})
    assert status == 400 and data["error"] == "token_expired"


def test_committed_openapi_matches_code():
    assert (ROOT / "docs" / "openapi.json").read_text() == render_openapi()
