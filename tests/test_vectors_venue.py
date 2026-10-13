"""v2 venue vectors (dex.* scopes, budget assets): reproducible, schema-valid, agreed on by Python and JavaScript,
and the same rules hold end to end through the environment's own decision point."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import jsonschema
import pytest

from autheo_agent_environment import schemas, vectors_venue
from autheo_agent_environment.delegation import issue_delegation, issue_invocation
from autheo_agent_environment.did import DidKey, Resolver
from autheo_agent_environment.didenv import DelegationLedger
from autheo_agent_environment.environment import Environment
from autheo_agent_environment.signing import Signer
from autheo_agent_environment.verifier import verify_bundle

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "autheo-v2-venue-vectors.json"
NODE = shutil.which("node")


def test_committed_venue_vectors_are_reproducible():
    assert VECTORS.read_text() == vectors_venue.render()


def test_venue_documents_validate_against_the_generated_json_schemas():
    data = json.loads(VECTORS.read_text())
    invocation = jsonschema.Draft202012Validator(schemas.build_schema("invocation", 2))
    for item in data["decision_cases"]:
        if item["name"] != "tampered_invocation":
            invocation.validate(item["invocation"])
    receipt = jsonschema.Draft202012Validator(schemas.build_schema("receipt", 2))
    for document in data["ledger"]["receipts"]:
        receipt.validate(document)
    outcomes = {item["name"]: item.get("expect_decision") or item["expect_error"] for item in data["decision_cases"]}
    assert outcomes["order_build_allow"] == "allow" and outcomes["order_build_escalate"] == "escalate"
    assert outcomes["widened_chain"] == outcomes["revoked_chain"] == "block"
    assert outcomes["forged_chain"] == "chain_not_authentic"


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_javascript_package_agrees_with_every_venue_vector():
    result = subprocess.run([NODE, str(ROOT / "interop" / "js" / "verify-venue-vectors.mjs"), str(VECTORS)],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert "agree with autheo-test-vectors/v2-venue" in result.stdout


def test_environment_records_the_budget_asset_and_refuses_cross_asset_spend():
    principal, agent = DidKey.from_seed(bytes([7]) * 32), DidKey.from_seed(bytes([8]) * 32)
    now = int(time.time())
    environment = Environment.ephemeral("venue:local", Signer.generate("autheo-test-authority"))
    try:
        ledger = DelegationLedger(environment, trusted_roots=[principal.did])
        chain = [issue_delegation(principal.signer, agent.did, {**vectors_venue.AGENT_CAP, "environments": ["venue:*"]},
                                  valid_from=now - 10, valid_until=now + 600)]

        def invoke(n, **fields):
            return issue_invocation(agent.signer, chain, request_id=f"req:{n}", environment="venue:local",
                                    action="dex.order.build", resource=vectors_venue.ASSET, created=now, **fields)

        allowed = ledger.evaluate(invoke(1, amount_minor=30_000, asset=vectors_venue.CASH))
        assert allowed["receipt"]["decision"] == "allow" and allowed["receipt"]["asset"] == vectors_venue.CASH
        assert verify_bundle(allowed["bundle"], resolver=Resolver(), trusted_roots=[principal.did])["valid"]
        other = ledger.evaluate(invoke(2, amount_minor=30_000, asset="DEMO"))
        assert other["receipt"]["decision"] == "block" and other["receipt"]["reasons"] == ["asset_mismatch"]
    finally:
        environment.close()
