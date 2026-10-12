"""Deterministic cross-language test vectors (tests/vectors/autheo-v1-vectors.json).

Ed25519 signatures are deterministic (RFC 8032), and every timestamp and jti is
fixed, so regeneration is byte-for-byte reproducible. The seeds below are PUBLIC
TEST VALUES derived from fixed strings; they must never be used for anything else.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import CANONICAL_JSON_ID, ZERO_HASH, canonical_json, chain_hash, digest
from .models import Checkpoint, Handoff, Mandate, OutcomeReport, Passport, ReceiptBody, Request
from .policy import DEFAULT_POLICY
from .signing import Signer, public_jwk, public_pem, raw_public

VECTOR_VERSION = "autheo-test-vectors/v1"
NOW = 1_790_000_000  # 2026-09-21T14:13:20Z
ISSUER = "autheo-test-authority"
AGENT = "agent:vector-01"
OWNER = "human:vector-owner"
ENVIRONMENT = "env:research"
DESTINATION = "env:review"


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"autheo-test-vector-seed:{label}".encode()).digest()


def _signer(issuer: str, label: str, kid: str) -> tuple[Signer, bytes]:
    seed = _seed(label)
    return Signer(issuer, Ed25519PrivateKey.from_private_bytes(seed), kid), seed


def _key_entry(signer: Signer, seed: bytes) -> dict:
    return {
        "id": signer.issuer,
        "kid": signer.kid,
        "public_key_pem": public_pem(signer.public_key),
        "public_key_raw_hex": raw_public(signer.public_key).hex(),
        "jwk": public_jwk(signer.public_key, signer.kid),
        "TEST_ONLY_private_seed_hex": seed.hex(),
    }


def _tamper_payload(token: str) -> str:
    header, payload, signature = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["body"]["amount_minor"] = claims["body"].get("amount_minor", 0) + 1
    encoded = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return ".".join([header, encoded, signature])


def _reheader(token: str, header: dict) -> str:
    _, payload, signature = token.split(".")
    encoded = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    return ".".join([encoded, payload, signature])


def canonical_cases() -> list[dict]:
    values = [
        ("empty_object", {}),
        ("empty_array", []),
        ("key_order_code_points", {"b": 1, "a": 2, "B": 3, "_": 4, "aa": 5}),
        ("nested", {"z": {"y": [3, 2, 1], "x": {"k": None}}, "a": [True, False]}),
        ("integers", {"max_safe": 2**53 - 1, "min_safe": -(2**53 - 1), "zero": 0, "neg": -7}),
        ("escapes", {"s": "quote\" backslash\\ slash/ nl\n tab\t cr\r bs\b ff\f ctl\u0001 del\u007f"}),
        ("non_ascii_bmp", {"s": "caf\u00e9 \u2014 \u65e5\u672c"}),
        ("astral_surrogate_pair", {"s": "clef \U0001d11e"}),
        ("mandate_body", Mandate(
            agent_id=AGENT, owner_id=OWNER, environment=ENVIRONMENT, scopes=["tool.invoke"],
            resources=["repo:jarvis"], tools=["git.status"], per_action_minor=10,
            total_budget_minor=100, approval_threshold_minor=5,
        ).model_dump(mode="json")),
    ]
    cases = [
        {"name": name, "value": value, "canonical": canonical_json(value).decode("ascii"), "sha256": digest(value)}
        for name, value in values
    ]
    # Inputs that MUST be rejected; given as JSON source text because they are not canonical values.
    cases += [
        {"name": "reject_float", "json": "{\"amount\":1.5}", "error": True},
        {"name": "reject_unsafe_integer", "json": "{\"n\":9007199254740992}", "error": True},
    ]
    return cases


def build() -> dict:
    authority, authority_seed = _signer(ISSUER, "issuer", "test-issuer-v1")
    agent_seed = _seed("agent")
    agent = Signer.for_agent(AGENT, Ed25519PrivateKey.from_private_bytes(agent_seed))
    stranger, _ = _signer(ISSUER, "stranger", "test-issuer-v1")

    passport = Passport(agent_id=AGENT, owner_id=OWNER, public_key=public_pem(agent.public_key),
                        environments=[ENVIRONMENT, DESTINATION])
    passport_token = authority.issue("passport", AGENT, "autheo-agent-environment", passport.model_dump(),
                                     ttl=86400, now=NOW, jti="00000000-0000-4000-8000-000000000001")
    mandate = Mandate(agent_id=AGENT, owner_id=OWNER, environment=ENVIRONMENT,
                      scopes=["tool.invoke", "compute.simulate", "environment.handoff"],
                      resources=["repo:jarvis"], destinations=[DESTINATION], tools=["git.status"],
                      per_action_minor=80, total_budget_minor=100, approval_threshold_minor=50)
    mandate_id = "00000000-0000-4000-8000-000000000002"
    mandate_token = authority.issue("mandate", AGENT, ENVIRONMENT, mandate.model_dump(), ttl=3600,
                                    now=NOW, jti=mandate_id)
    request = Request(request_id="req:vector-allow", agent_id=AGENT, environment=ENVIRONMENT,
                      mandate_id=mandate_id, action="tool.invoke", resource="repo:jarvis",
                      tool="git.status", amount_minor=40)
    request_token = agent.issue("request", AGENT, ENVIRONMENT, request.model_dump(), ttl=300, now=NOW + 5,
                                jti="00000000-0000-4000-8000-000000000003")
    outcome = OutcomeReport(request_id="req:vector-allow", agent_id=AGENT, environment=ENVIRONMENT,
                            status="succeeded", detail_sha256=digest({"exit_code": 0}))
    outcome_token = agent.issue("outcome", AGENT, ENVIRONMENT, outcome.model_dump(), ttl=300, now=NOW + 20,
                                jti="00000000-0000-4000-8000-000000000004")

    # A three-receipt chain: allow -> escalate -> block, then an outcome report.
    receipts, previous = [], ZERO_HASH
    plan = [
        ("req:vector-allow", "simulation", "allow", ["within_demo_policy"], 40, None),
        ("req:vector-escalate", "simulation", "escalate", ["human_review_required"], 51, None),
        ("req:vector-block", "simulation", "block", ["per_action_limit", "total_budget_limit"], 81, None),
        ("outcome:req:vector-allow", "outcome_report", "recorded",
         ["executor_reported_succeeded", "not_independently_verified"], 0, "req:vector-allow"),
    ]
    for index, (request_id, kind, decision, reasons, amount, reference) in enumerate(plan, 1):
        body = ReceiptBody(
            sequence=index, previous_hash=previous, request_id=request_id,
            payload_hash=digest({"vector": request_id}), agent_id=AGENT, mandate_id=mandate_id, kind=kind,
            decision=decision, reasons=reasons, amount_minor=amount, recorded_at=NOW + 10 * index,
            action="tool.invoke", resource="repo:jarvis", tool="git.status",
            policy_id=DEFAULT_POLICY.policy_id if kind == "simulation" else None,
            policy_digest=DEFAULT_POLICY.digest if kind == "simulation" else None,
            reference=reference,
            reported_status="succeeded" if kind == "outcome_report" else None,
            reported_by="agent_signed" if kind == "outcome_report" else None,
        ).model_dump(mode="json", exclude_none=True)
        token = authority.issue("receipt", AGENT, ENVIRONMENT, body, ttl=86400, now=NOW + 10 * index,
                                jti=f"00000000-0000-4000-8000-0000000001{index:02d}")
        link = chain_hash(previous, token)
        receipts.append({"sequence": index, "request_id": request_id, "token": token,
                         "previous_hash": previous, "chain_hash": link, "body": body})
        previous = link

    checkpoint = Checkpoint(task_id="task:vector", step="awaiting_review", artifact_sha256=digest({"demo": True}))
    handoff = Handoff(agent_id=AGENT, owner_id=OWNER, source_environment=ENVIRONMENT,
                      destination_environment=DESTINATION, source_mandate_id=mandate_id,
                      passport_digest=digest(passport_token), scopes=["tool.invoke"], checkpoint=checkpoint,
                      source_audit_head=previous)
    handoff_token = authority.issue("handoff", AGENT, DESTINATION, handoff.model_dump(), ttl=300, now=NOW + 60,
                                    jti="00000000-0000-4000-8000-000000000005")

    def doc(name, kind, token, issuer, audience, key, verify_at, valid=True, error=None, historical=False):
        entry = {"name": name, "kind": kind, "typ": f"autheo-{kind}+jwt", "token": token, "issuer": issuer,
                 "audience": audience, "key": key, "verify_at": verify_at, "historical": historical,
                 "expect_valid": valid}
        if error:
            entry["expect_error"] = error
        return entry

    receipt_token = receipts[0]["token"]
    documents = [
        doc("passport", "passport", passport_token, ISSUER, "autheo-agent-environment", ISSUER, NOW + 30),
        doc("mandate", "mandate", mandate_token, ISSUER, ENVIRONMENT, ISSUER, NOW + 30),
        doc("request_agent_signed", "request", request_token, AGENT, ENVIRONMENT, AGENT, NOW + 30),
        doc("outcome_agent_signed", "outcome", outcome_token, AGENT, ENVIRONMENT, AGENT, NOW + 30),
        doc("handoff", "handoff", handoff_token, ISSUER, DESTINATION, ISSUER, NOW + 90),
        doc("receipt_historical_after_expiry", "receipt", receipt_token, ISSUER, ENVIRONMENT, ISSUER,
            NOW + 10 * 86400, historical=True),
        doc("mandate_expired", "mandate", mandate_token, ISSUER, ENVIRONMENT, ISSUER, NOW + 3600,
            valid=False, error="expired"),
        doc("mandate_not_yet_valid", "mandate", mandate_token, ISSUER, ENVIRONMENT, ISSUER, NOW - 10,
            valid=False, error="not_yet_valid"),
        doc("receipt_tampered_payload", "receipt", _tamper_payload(receipt_token), ISSUER, ENVIRONMENT, ISSUER,
            NOW + 30, valid=False, error="bad_signature", historical=True),
        doc("receipt_signed_by_other_key", "receipt",
            stranger.issue("receipt", AGENT, ENVIRONMENT, receipts[0]["body"], ttl=86400, now=NOW + 10,
                           jti="00000000-0000-4000-8000-000000000199"),
            ISSUER, ENVIRONMENT, ISSUER, NOW + 30, valid=False, error="bad_signature", historical=True),
        doc("receipt_alg_hs256_header", "receipt",
            _reheader(receipt_token, {"alg": "HS256", "kid": "test-issuer-v1", "typ": "autheo-receipt+jwt"}),
            ISSUER, ENVIRONMENT, ISSUER, NOW + 30, valid=False, error="bad_header", historical=True),
        doc("receipt_alg_none_header", "receipt",
            _reheader(receipt_token, {"alg": "none", "kid": "test-issuer-v1", "typ": "autheo-receipt+jwt"}),
            ISSUER, ENVIRONMENT, ISSUER, NOW + 30, valid=False, error="bad_header", historical=True),
        doc("mandate_presented_as_receipt", "receipt", mandate_token, ISSUER, ENVIRONMENT, ISSUER, NOW + 30,
            valid=False, error="bad_header", historical=True),
        doc("receipt_wrong_audience", "receipt", receipt_token, ISSUER, DESTINATION, ISSUER, NOW + 30,
            valid=False, error="bad_claims", historical=True),
    ]
    tampered_chain = [dict(r) for r in receipts]
    tampered_chain[1] = {**tampered_chain[1], "chain_hash": "f" * 64}
    return {
        "version": VECTOR_VERSION,
        "canonical_json": CANONICAL_JSON_ID,
        "spec": "docs/SPEC-SIGNATURES.md",
        "generated_by": "python -m autheo_agent_environment vectors generate",
        "warning": "All private seeds in this file are PUBLIC TEST VALUES. Never use them outside tests.",
        "clock_skew_seconds": 2,
        "keys": {ISSUER: _key_entry(authority, authority_seed), AGENT: _key_entry(agent, agent_seed)},
        "canonical": canonical_cases(),
        "documents": documents,
        "chain": {
            "environment": ENVIRONMENT,
            "issuer": ISSUER,
            "genesis_previous_hash": ZERO_HASH,
            "link_rule": "chain_hash = lowercase_hex(sha256(ascii(previous_hash) || ascii(receipt_jws)))",
            "receipts": receipts,
            "head": previous,
        },
        "tampered_chain": {
            "description": "Receipt 2 has a forged chain_hash; verifiers must report sequence 2.",
            "receipts": tampered_chain,
            "first_invalid_sequence": 2,
        },
        "digests": {
            "passport_digest": digest(passport_token),
            "default_policy_digest": DEFAULT_POLICY.digest,
            "default_policy": DEFAULT_POLICY.model_dump(mode="json"),
        },
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write(path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(render(), encoding="utf-8")
