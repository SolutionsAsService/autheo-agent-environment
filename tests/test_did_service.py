"""DID operations through the HTTP API and the CLI (service conveniences around the offline core)."""

from __future__ import annotations

import json
import threading
import time
from http.client import HTTPConnection

import pytest

from autheo_agent_environment.api import create_api_server
from autheo_agent_environment.cli import main
from autheo_agent_environment.delegation import issue_delegation, issue_invocation, issue_revocation
from autheo_agent_environment.did import DidKey, Resolver
from autheo_agent_environment.service import TrustService
from autheo_agent_environment.signing import Signer, public_pem
from autheo_agent_environment.verifier import verify_bundle

ROOT_CAP = {"environments": ["env:*"], "scopes": ["compute.simulate", "marketplace.read"], "resources": ["listing:*"],
            "per_action_minor": 80, "total_budget_minor": 100, "approval_threshold_minor": 50,
            "max_delegation_depth": 1}
SUB_CAP = {"environments": ["env:research"], "scopes": ["compute.simulate"], "resources": ["listing:demo-01"],
           "per_action_minor": 30, "total_budget_minor": 50, "approval_threshold_minor": 20}


class Client:
    def __init__(self, server, token):
        self.port, self.token = server.server_port, token

    def call(self, method, path, payload=None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        connection.request(method, path, body=json.dumps(payload) if payload is not None else None, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read() or b"{}")
        connection.close()
        return response.status, data

    def ok(self, method, path, payload=None):
        status, data = self.call(method, path, payload)
        assert status == 200, data
        return data


@pytest.fixture
def api():
    service = TrustService.ephemeral(environments=["env:research", "env:review"])
    server = create_api_server(service, service.state.api_token, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield Client(server, service.state.api_token), service
    server.shutdown()
    server.server_close()
    service.close()
    thread.join(timeout=2)


def test_full_permissionless_flow_over_the_api(api):
    client, service = api
    human, agent, sub = (client.ok("POST", "/v1/dids", {})["did"] for _ in range(3))
    assert human.startswith("did:key:z6Mk") and set(client.ok("GET", "/v1/dids")["dids"]) == {human, agent, sub}
    resolved = client.ok("GET", f"/v1/dids/{human}")
    assert resolved["document"]["id"] == human and resolved["network_used"] is False
    assert client.ok("POST", "/v1/trust-roots", {"environment": "env:research", "did": human})["trusted_roots"] == [human]

    root = client.ok("POST", "/v1/delegations", {"issuer": human, "subject": agent, "capability": ROOT_CAP})
    chain = client.ok("POST", "/v1/delegations", {"issuer": agent, "subject": sub, "capability": SUB_CAP,
                                                  "parent_chain": root["chain"], "ttl_seconds": 600})["chain"]
    widened = client.call("POST", "/v1/delegations", {"issuer": agent, "subject": sub, "parent_chain": root["chain"],
                                                      "capability": {**SUB_CAP, "per_action_minor": 90,
                                                                     "total_budget_minor": 90}})
    assert widened[0] == 400 and "not an attenuation" in widened[1]["detail"]

    verified = client.ok("POST", "/v1/delegations/verify", {"chain": chain, "trusted_roots": [human]})
    assert verified["valid"] and verified["depth"] == 2 and verified["root"] == human

    def act(**fields):
        request = {"invoker": sub, "chain": chain, "environment": "env:research", "action": "compute.simulate",
                   "resource": "listing:demo-01", "amount_minor": 10, **fields}
        return client.ok("POST", "/v1/invocations/evaluate", {"request": request})

    allowed = act()
    assert allowed["outcome"] == "allow" and allowed["request_proof"] == "service_held_key_local_dev"
    blocked = act(action="marketplace.read")
    assert blocked["outcome"] == "block" and blocked["reasons"] == ["scope_denied"]
    review = client.call("POST", "/v1/invocations/evaluate", {"request": {
        "invoker": sub, "chain": chain, "environment": "env:review", "action": "compute.simulate",
        "resource": "listing:demo-01"}})
    assert review[0] == 200 and review[1]["reasons"][0] == "delegation_untrusted_root:0"

    revoked = client.ok("POST", "/v1/revocations", {"issuer": agent, "chain": chain, "reason": "rotated"})
    assert set(revoked["receipts"]) == {"env:research", "env:review"}
    assert act()["reasons"][0] == "delegation_revoked:1"
    listing = client.ok("GET", "/v1/revocations?environment=env:research")
    assert listing["records"] == [revoked["revocation"]]

    bundle_report = client.ok("POST", "/v1/bundles/verify", {"bundle": allowed["bundle"], "trusted_roots": [human]})
    assert bundle_report["verdict"] == "allow_verified"
    offline = verify_bundle(allowed["bundle"], resolver=Resolver(), trusted_roots=[human],
                            environment_did=service.info()["authority_did"])
    assert offline["valid"]
    export = client.ok("GET", "/v1/ledger/v2?environment=env:research")
    assert len(export["receipts"]) == 4 and export["issuer"] == service.info()["authority_did"]
    ledger = client.ok("GET", "/v1/ledger/verify?environment=env:research")
    assert ledger["valid"] and ledger["v2"]["count"] == 4


def test_signed_documents_from_agent_held_keys(api):
    client, service = api
    human, agent = DidKey.generate(), DidKey.generate()
    client.ok("POST", "/v1/trust-roots", {"environment": "env:research", "did": human.did})
    now = int(time.time())
    delegation = issue_delegation(human.signer, agent.did, ROOT_CAP, valid_from=now - 5, valid_until=now + 600)
    invocation = issue_invocation(agent.signer, [delegation], request_id="req:held-1", environment="env:research",
                                  action="compute.simulate", resource="listing:anything", amount_minor=60, created=now)
    result = client.ok("POST", "/v1/invocations/evaluate", {"invocation": invocation})
    assert result["outcome"] == "escalate" and result["request_proof"] == "invoker_signed"
    assert client.ok("POST", "/v1/invocations/evaluate", {"invocation": invocation})["replayed"] is True
    invocation["amount_minor"] = 1
    status, error = client.call("POST", "/v1/invocations/evaluate", {"invocation": invocation})
    assert status == 400 and error["error"] == "proof_invalid" and error["code"] == "bad_signature"
    record = issue_revocation(human.signer, delegation, revoked_at=now)
    assert client.ok("POST", "/v1/revocations", {"revocation": record})["revocation"] == record
    status, error = client.call("POST", "/v1/delegations", {"issuer": human.did, "subject": agent.did,
                                                            "capability": ROOT_CAP})
    assert status == 400 and "not held by this local service" in error["detail"]


def test_api_errors_and_schemas(api):
    client, _ = api
    assert client.call("GET", "/v1/dids/did:example:123")[1]["error"] == "did_invalid"
    assert client.call("GET", "/v1/dids/did:web:example.com")[1]["code"] == "notFound"
    assert client.call("POST", "/v1/bundles/verify", {"bundle": {}})[0] == 400  # no root named, no any_root
    assert client.call("POST", "/v1/invocations/evaluate", {})[0] == 400
    assert client.call("POST", "/v1/invocations/evaluate", {"invocation": {"environment": "env:none"}})[0] == 404
    names = client.ok("GET", "/v1/schemas")["schemas_v2"]
    assert "delegation" in names
    schema = client.ok("GET", "/v1/schemas/v2/delegation")
    assert schema["$id"] == "urn:autheo:schema:delegation:v2"
    assert client.call("GET", "/v1/schemas/v2/nope")[0] == 404
    info = client.ok("GET", "/v1/info")
    assert info["authority_did"].startswith("did:key:") and info["did_methods"]["did:web"] == "cache_only"


def test_identities_expose_the_did_of_the_agent_key(api):
    client, _ = api
    agent = Signer.generate("agent:did-1")
    agent = Signer.for_agent(agent.issuer, agent.key)
    identity = client.ok("POST", "/v1/identities", {
        "agent_id": agent.issuer, "owner_id": "human:owner", "environments": ["env:research"],
        "public_key": public_pem(agent.public_key)})
    assert identity["did"] == DidKey(agent.key).did


@pytest.fixture
def cli(tmp_path, capsys):
    state = tmp_path / "state"

    def run(*argv, code=0):
        result = main(["--state-dir", str(state), *argv])
        captured = capsys.readouterr()
        assert result == code, (captured.out, captured.err)
        text = captured.out if code == 0 or captured.out else captured.err
        return json.loads(text) if text.strip() else None

    run("init", "--environment", "env:research")
    return run, tmp_path


def test_cli_offline_delegation_invocation_and_verification(cli):
    run, tmp = cli
    human = run("did", "create", "--out", str(tmp / "human.json"), "--seed-hex", "01" * 32)
    agent = run("did", "create", "--out", str(tmp / "agent.json"))
    sub = run("did", "create", "--out", str(tmp / "sub.json"))
    assert (tmp / "human.json").stat().st_mode & 0o077 == 0
    run("did", "create", "--out", str(tmp / "human.json"), code=2)  # never overwrites a key
    assert run("did", "resolve", human["did"])["document"]["id"] == human["did"]
    assert "keyAgreement" in run("did", "resolve", human["did"], "--encryption-key")["document"]
    run("did", "delegate", "--key", str(tmp / "human.json"), "--to", agent["did"], "--environment", "env:*",
        "--scope", "compute.simulate", "--scope", "marketplace.read", "--resource", "listing:*", "--per-action", "80",
        "--total", "100", "--threshold", "50", "--depth", "1", "--out", str(tmp / "chain1.json"))
    run("did", "delegate", "--key", str(tmp / "agent.json"), "--to", sub["did"], "--parent", str(tmp / "chain1.json"),
        "--environment", "env:research", "--scope", "compute.simulate", "--resource", "listing:demo-01",
        "--per-action", "30", "--total", "50", "--threshold", "20", "--out", str(tmp / "chain2.json"))
    run("did", "delegate", "--key", str(tmp / "sub.json"), "--to", human["did"], "--parent", str(tmp / "chain2.json"),
        "--environment", "env:research", "--scope", "compute.simulate", "--resource", "listing:demo-01",
        "--per-action", "30", "--total", "50", "--threshold", "20", code=2)  # depth exhausted
    run("did", "invoke", "--key", str(tmp / "sub.json"), "--chain", str(tmp / "chain2.json"), "--environment",
        "env:research", "--action", "compute.simulate", "--resource", "listing:demo-01", "--amount", "10",
        "--out", str(tmp / "inv.json"))
    assert run("did", "verify", "chain", str(tmp / "inv.json"), "--root", human["did"])["valid"]

    run("did", "trust", "--environment", "env:research", "--root", human["did"])
    result = run("did", "evaluate", "--invocation", str(tmp / "inv.json"), "--bundle-out", str(tmp / "bundle.json"))
    assert result["outcome"] == "allow"
    info = run("info")
    assert run("did", "verify", "bundle", str(tmp / "bundle.json"), "--root", human["did"],
               "--environment-did", info["authority_did"])["verdict"] == "allow_verified"

    run("did", "revoke", "--key", str(tmp / "agent.json"), "--chain", str(tmp / "chain2.json"),
        "--out", str(tmp / "rev.json"))
    run("did", "record-revocation", str(tmp / "rev.json"))
    run("did", "revocations", "--environment", "env:research", "--out", str(tmp / "revs.json"))
    report = run("did", "verify", "chain", str(tmp / "chain2.json"), "--root", human["did"], "--revocations",
                 str(tmp / "revs.json"), code=1)
    assert report["errors"][0]["code"] == "revoked"
    export = run("did", "ledger", "export", "--environment", "env:research", "--out", str(tmp / "ledger.json"))
    assert export["count"] == 2
    assert run("did", "ledger", "verify", "--environment", "env:research", "--expected-head", export["head"])["valid"]
    assert run("did", "verify", "ledger", str(tmp / "ledger.json"), "--issuer", info["authority_did"])["valid"]
    assert run("did", "create", "--service")["custody"] == "local_dev_custody"
    run("did", "revoke", "--key", str(tmp / "agent.json"), "--chain", str(tmp / "chain2.json"), "--index", "5",
        code=2)


def test_cli_key_mapping_and_did_web_cache(cli):
    run, tmp = cli
    agent = Signer.generate("agent:map")
    (tmp / "agent.pub.pem").write_text(public_pem(agent.public_key))
    mapped = run("did", "from-key", "--public-key-file", str(tmp / "agent.pub.pem"))
    assert mapped["did"] == DidKey(agent.key).did and mapped["v1_kid"].startswith("sha256:")
    key = DidKey.generate()
    did = "did:web:agents.example:alice"
    method = {"id": f"{did}#key-1", "type": "Multikey", "controller": did, "publicKeyMultibase": key.did.split(":")[2]}
    (tmp / "did.json").write_text(json.dumps({"id": did, "verificationMethod": [method],
                                              "assertionMethod": [method["id"]]}))
    run("did", "web-cache", "add", str(tmp / "did.json"), "--did-web-cache", str(tmp / "cache"))
    assert run("did", "resolve", did, "--did-web-cache", str(tmp / "cache"))["document"]["id"] == did
    assert run("did", "resolve", "did:web:other.example", code=2)["error"] == "did_invalid"
