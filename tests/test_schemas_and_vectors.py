import json
import shutil
import subprocess
from pathlib import Path

import jwt
import pytest
from jsonschema import Draft202012Validator

from autheo_agent_environment import schemas, vectors
from autheo_agent_environment.canonical import canonical_json, digest
from autheo_agent_environment.ledger import verify_rows
from autheo_agent_environment.policy import DEFAULT_POLICY
from autheo_agent_environment.signing import read_public, unverified_claims, verify

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "autheo-v1-vectors.json"


def schema(name):
    document = json.loads((ROOT / "schemas" / f"{name}.v1.schema.json").read_text())
    Draft202012Validator.check_schema(document)
    return Draft202012Validator(document)


@pytest.fixture(scope="module")
def data():
    return json.loads(VECTORS.read_text())


def test_committed_schemas_match_models():
    assert schemas.check(ROOT / "schemas") == []
    for name in schemas.SCHEMAS:
        assert schema(name).schema["$id"] == f"urn:autheo:schema:{name}:v1"


def test_schema_check_reports_drift(tmp_path):
    schemas.export(tmp_path)
    (tmp_path / "receipt.v1.schema.json").write_text("{}")
    (tmp_path / "policy.v1.schema.json").unlink()
    assert sorted(schemas.check(tmp_path)) == ["policy.v1.schema.json", "receipt.v1.schema.json"]


def test_committed_vectors_are_reproducible():
    assert VECTORS.read_text() == vectors.render()


def test_vector_documents_validate_against_json_schemas(data):
    header_schema, claims_schema = schema("jws-header"), schema("jws-claims")
    for document in data["documents"]:
        if not document["expect_valid"]:
            continue
        claims = unverified_claims(document["token"])
        header_schema.validate(jwt.get_unverified_header(document["token"]))
        claims_schema.validate(claims)
        schema(document["kind"]).validate(claims["body"])
    receipt_schema = schema("receipt")
    entry_schema = schema("ledger-entry")
    for receipt in data["chain"]["receipts"]:
        receipt_schema.validate(receipt["body"])
        entry_schema.validate({k: receipt[k] for k in ("sequence", "request_id", "token", "chain_hash")})
    schema("policy").validate(DEFAULT_POLICY.model_dump(mode="json"))
    assert not receipt_schema.is_valid({**data["chain"]["receipts"][0]["body"], "executed": True})
    assert not receipt_schema.is_valid({**data["chain"]["receipts"][0]["body"], "surprise": 1})


def test_canonical_vectors(data):
    for case in data["canonical"]:
        if case.get("error"):
            with pytest.raises(ValueError):
                canonical_json(json.loads(case["json"]))
        else:
            assert canonical_json(case["value"]).decode() == case["canonical"]
            assert digest(case["value"]) == case["sha256"]


ERRORS = {
    "bad_signature": jwt.InvalidSignatureError,
    "expired": jwt.ExpiredSignatureError,
    "not_yet_valid": jwt.ImmatureSignatureError,
    "bad_claims": jwt.InvalidTokenError,
}


def test_python_verifier_agrees_with_vector_expectations(data):
    for document in data["documents"]:
        key = data["keys"][document["key"]]
        args = (document["token"], document["kind"], read_public(key["public_key_pem"]), document["issuer"],
                document["audience"], key["kid"], document["historical"], document["verify_at"])
        if document["expect_valid"]:
            assert verify(*args)["iss"] == document["issuer"], document["name"]
            continue
        expected = ERRORS.get(document["expect_error"], (ValueError, jwt.InvalidTokenError))
        with pytest.raises(expected):
            verify(*args)


def test_python_chain_verification_matches_vectors(data):
    key = data["keys"][data["chain"]["issuer"]]
    public_key = read_public(key["public_key_pem"])

    def rows(receipts):
        return [(r["sequence"], r["request_id"], r["token"], r["chain_hash"]) for r in receipts]

    good = verify_rows(rows(data["chain"]["receipts"]), public_key, data["chain"]["issuer"],
                       data["chain"]["environment"], key["kid"])
    assert good["valid"] and good["head"] == data["chain"]["head"]
    bad = verify_rows(rows(data["tampered_chain"]["receipts"]), public_key, data["chain"]["issuer"],
                      data["chain"]["environment"], key["kid"])
    assert bad["first_invalid_sequence"] == data["tampered_chain"]["first_invalid_sequence"]
    assert data["digests"]["default_policy_digest"] == DEFAULT_POLICY.digest


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_javascript_reference_verifier_agrees():
    result = subprocess.run(
        ["node", str(ROOT / "interop" / "js" / "verify-vectors.mjs"), str(VECTORS)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("OK ")
