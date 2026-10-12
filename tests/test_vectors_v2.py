"""v2 vectors: reproducible, schema-valid, and agreed on by the Python and JavaScript implementations."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import jsonschema
import pytest

from autheo_agent_environment import schemas, vectors_v2
from autheo_agent_environment.delegation import issue_invocation, verify_chain, verify_invocation
from autheo_agent_environment.did import DidKey, Resolver
from autheo_agent_environment.jcs import canonicalize
from autheo_agent_environment.verifier import verify_bundle, verify_receipts

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "autheo-v2-vectors.json"
NODE = shutil.which("node")


@pytest.fixture(scope="module")
def data():
    return json.loads(VECTORS.read_text())


def test_committed_v2_vectors_are_reproducible():
    assert VECTORS.read_text() == vectors_v2.render()


def test_v1_vectors_are_untouched():
    from autheo_agent_environment import vectors

    assert (ROOT / "tests" / "vectors" / "autheo-v1-vectors.json").read_text() == vectors.render()


def _validator(name):
    return jsonschema.Draft202012Validator(schemas.build_schema(name, 2))


def test_v2_documents_validate_against_the_generated_json_schemas(data):
    delegation, invocation = _validator("delegation"), _validator("invocation")
    for document in data["delegations"].values():
        delegation.validate(document)
    for item in data["invocation_cases"]:
        if item["name"] != "tampered":
            invocation.validate(item["invocation"])
    _validator("revocation").validate(data["revocations"]["agent_revokes_agent_to_subagent"])
    for receipt in data["ledger"]["receipts"]:
        _validator("receipt").validate(receipt)
    _validator("ledger-export").validate(data["ledger"])
    _validator("bundle").validate(data["bundle_cases"][0]["bundle"])
    _validator("did-key-document").validate(data["primitives"]["did_key"][1]["document"])
    assert schemas.check(ROOT / "schemas") == []


def test_python_agrees_with_every_chain_invocation_and_bundle_case(data):
    for item in data["chain_cases"]:
        result = verify_chain(item["chain"], resolver=Resolver(), at=item["at"], trusted_roots=item["trusted_roots"],
                              revocations=item["revocations"])
        pairs = []
        for error in result.errors:
            if [error.index, error.code] not in pairs:
                pairs.append([error.index, error.code])
        assert (result.valid, pairs) == (item["expect_valid"], item["expect_errors"]), item["name"]
    for item in data["bundle_cases"]:
        report = verify_bundle(item["bundle"], resolver=Resolver(), trusted_roots=item["trusted_roots"],
                               environment_did=item["environment_did"], extra_revocations=item["revocations"])
        assert report["problems"] == item["expect_problems"], item["name"]
    ledger = data["ledger"]
    assert verify_receipts(ledger["receipts"], resolver=Resolver(), issuer=ledger["issuer"])["head"] == ledger["head"]


def test_primitive_vectors(data):
    for item in data["primitives"]["jcs"]:
        if item.get("error"):
            with pytest.raises(ValueError):
                canonicalize(json.loads(item["json"]))
        else:
            assert canonicalize(json.loads(item["json"])).decode() == item["canonical"]
    for item in data["primitives"]["did_key"]:
        if "seed_hex" in item:
            assert DidKey.from_seed(bytes.fromhex(item["seed_hex"])).did == item["did"]


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_javascript_agrees_with_every_v2_vector():
    result = subprocess.run([NODE, str(ROOT / "interop" / "js" / "verify-v2-vectors.mjs"), str(VECTORS)],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert "agree with autheo-test-vectors/v2" in result.stdout


@pytest.mark.skipif(NODE is None, reason="node is not installed")
def test_javascript_signed_invocation_is_identical_to_python_and_verifies(data):
    result = subprocess.run([NODE, str(ROOT / "interop" / "js" / "sign-v2-invocation.mjs"), str(VECTORS)],
                            capture_output=True, text=True, timeout=60, check=True)
    js_signed = json.loads(result.stdout)
    subagent = DidKey.from_seed(bytes.fromhex(data["keys"]["subagent"]["TEST_ONLY_seed_hex"]))
    chain = [data["delegations"]["root_to_agent"], data["delegations"]["agent_to_subagent"]]
    py_signed = issue_invocation(subagent.signer, chain, request_id="req:v2-js", environment="env:research",
                                 action="compute.simulate", resource="listing:demo-01", amount_minor=7,
                                 created=data["now"] + 10)
    assert canonicalize(js_signed) == canonicalize(py_signed)
    verified = verify_invocation(js_signed, resolver=Resolver(), at=data["now"] + 20,
                                 trusted_roots=[data["keys"]["root"]["did"]])
    assert verified.chain.valid and verified.invocation.invoker == subagent.did
