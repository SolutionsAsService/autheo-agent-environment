"""OpenAPI 3.1 description of the local trust API, generated from the strict models.

docs/openapi.json is a committed rendering of build_openapi(); tests fail on drift.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic.json_schema import models_json_schema

from . import __version__
from .models import Decision, ReceiptBody
from .models_v2 import Bundle, Delegation, Invocation, ReceiptV2, Revocation, RevocationList
from .policy import PolicyDocument
from .service import (
    CheckpointInput,
    EvaluateInput,
    HandoffAcceptInput,
    IdentityIssueInput,
    LedgerVerifyInput,
    MandateGrantInput,
    OutcomeInput,
    RevokeInput,
    VerifyReceiptInput,
)
from .service_did import (
    BundleVerifyInput,
    ChainVerifyInput,
    DelegateInput,
    DidCreateInput,
    InvocationEvaluateInput,
    RevocationInput,
    TrustRootInput,
)

COMPONENT_MODELS = [
    IdentityIssueInput,
    MandateGrantInput,
    RevokeInput,
    EvaluateInput,
    OutcomeInput,
    VerifyReceiptInput,
    LedgerVerifyInput,
    CheckpointInput,
    HandoffAcceptInput,
    Decision,
    ReceiptBody,
    PolicyDocument,
    DidCreateInput,
    TrustRootInput,
    DelegateInput,
    RevocationInput,
    InvocationEvaluateInput,
    ChainVerifyInput,
    BundleVerifyInput,
    Delegation,
    Invocation,
    Revocation,
    RevocationList,
    ReceiptV2,
    Bundle,
]


def _ref(name: str) -> dict:
    return {"$ref": f"#/components/schemas/{name}"}


def _receipt_envelope() -> dict:
    return {
        "type": "object",
        "properties": {
            "receipt": {"allOf": [_ref("ReceiptBody")], "description": "Receipt body plus chain hash"},
            "receipt_token": {"type": ["string", "null"], "description": "Signed autheo-receipt+jwt"},
        },
    }


def _op(summary: str, *, body: str | None = None, response: dict | None = None, public: bool = False,
        params: list | None = None, errors=(400, 401, 404)) -> dict:
    operation = {
        "summary": summary,
        "responses": {
            "200": {
                "description": "OK",
                "content": {"application/json": {"schema": response or {"type": "object"}}},
            }
        },
    }
    for status in errors:
        if public and status == 401:
            continue
        operation["responses"][str(status)] = {"$ref": f"#/components/responses/E{status}"}
    if body:
        operation["requestBody"] = {"required": True, "content": {"application/json": {"schema": _ref(body)}}}
    if public:
        operation["security"] = []
    if params:
        operation["parameters"] = params
    return operation


def _path_param(name: str) -> dict:
    return {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}


def _query(name: str, required: bool = False, schema: dict | None = None) -> dict:
    return {"name": name, "in": "query", "required": required, "schema": schema or {"type": "string"}}


def build_openapi() -> dict:
    _, definitions = models_json_schema(
        [(model, "validation") for model in COMPONENT_MODELS], ref_template="#/components/schemas/{model}"
    )
    schemas = definitions.get("$defs", {})
    errors = {
        str(code): {
            "description": text,
            "content": {"application/json": {"schema": {
                "type": "object",
                "required": ["error"],
                "properties": {"error": {"type": "string"}, "detail": {"type": "string"}},
            }}},
        }
        for code, text in [
            (400, "Validation, signature, expiry or policy-input rejection"),
            (401, "Missing or wrong bearer token"),
            (404, "Unknown identity, mandate, receipt, environment or route"),
            (409, "Idempotency or replay conflict"),
            (413, "Body larger than 64 KiB"),
            (415, "Content-Type must be application/json"),
            (421, "Host header is not a loopback name with the bound port"),
        ]
    }
    responses = {f"E{code}": value for code, value in errors.items()}
    write_errors = (400, 401, 404, 409, 413, 415)
    decision_response = {
        "type": "object",
        "properties": {
            "decision": {"anyOf": [_ref("Decision"), {"type": "null"}],
                         "description": "Null when an identical request_id is replayed"},
            "outcome": {"enum": ["allow", "escalate", "block"]},
            "reasons": {"type": "array", "items": {"type": "string"}},
            "replayed": {"type": "boolean"},
            "request_proof": {"enum": ["agent_signed_request", "service_held_key_local_dev"]},
            "executed": {"const": False},
            **_receipt_envelope()["properties"],
        },
    }
    paths = {
        "/v1/health": {"get": _op("Liveness and mode", public=True, errors=())},
        "/v1/openapi.json": {"get": _op("This document", public=True, errors=())},
        "/v1/schemas": {"get": _op("List versioned JSON Schemas", public=True, errors=())},
        "/v1/schemas/{name}": {"get": _op("One JSON Schema (draft 2020-12)", public=True,
                                          params=[_path_param("name")], errors=(404,))},
        "/v1/info": {"get": _op("Issuer, key id, public key, environments and active policy digest")},
        "/v1/policy": {"get": _op("Active declarative policy and digest", response={
            "type": "object", "properties": {"policy": _ref("PolicyDocument"), "policy_digest": {"type": "string"}}})},
        "/v1/identities": {"post": _op("Issue an agent passport (agent-held public key, or local-dev generated key)",
                                       body="IdentityIssueInput", errors=write_errors)},
        "/v1/identities/{agent_id}": {"get": _op("Identity status", params=[_path_param("agent_id")])},
        "/v1/identities/{agent_id}/revoke": {"post": _op("Revoke the agent passport in every environment",
                                                         body="RevokeInput", params=[_path_param("agent_id")],
                                                         errors=write_errors)},
        "/v1/mandates": {"post": _op("Grant a scoped, budgeted, short-lived mandate", body="MandateGrantInput",
                                     response=_receipt_envelope(), errors=write_errors)},
        "/v1/mandates/{mandate_id}": {"get": _op("Mandate status: spent, remaining, revoked, expiry",
                                                 params=[_path_param("mandate_id")])},
        "/v1/mandates/{mandate_id}/revoke": {"post": _op("Revoke a mandate (recorded as a signed receipt)",
                                                         body="RevokeInput", params=[_path_param("mandate_id")],
                                                         response=_receipt_envelope(), errors=write_errors)},
        "/v1/evaluate": {"post": _op("Evaluate one action; records a signed decision receipt. Never executes.",
                                     body="EvaluateInput", response=decision_response, errors=write_errors)},
        "/v1/receipts/outcome": {"post": _op("Record an executor-reported outcome for an allowed decision",
                                             body="OutcomeInput", response=_receipt_envelope(),
                                             errors=write_errors)},
        "/v1/receipts/verify": {"post": _op("Verify a receipt signature and its ledger membership",
                                            body="VerifyReceiptInput", errors=write_errors)},
        "/v1/ledger/receipts": {"get": _op("List recent receipts with tokens", params=[
            _query("environment", True), _query("agent_id"),
            _query("limit", schema={"type": "integer", "minimum": 1, "maximum": 500})])},
        "/v1/ledger/verify": {
            "get": _op("Verify a ledger (signatures, links, identity, triggers, optional anchor)",
                       params=[_query("environment", True), _query("expected_head")]),
            "post": _op("Verify a ledger", body="LedgerVerifyInput", errors=write_errors),
        },
        "/v1/checkpoints": {"post": _op("Export a destination-bound signed checkpoint (handoff)",
                                        body="CheckpointInput", errors=write_errors)},
        "/v1/handoffs/accept": {"post": _op("Admit a checkpoint at its destination; grants no authority",
                                            body="HandoffAcceptInput", response=_receipt_envelope(),
                                            errors=write_errors)},
        "/v1/dids": {
            "get": _op("DIDs whose keys this local service holds (local-dev custody)"),
            "post": _op("Generate a did:key with local-dev custody (no registration anywhere)", body="DidCreateInput",
                        errors=write_errors),
        },
        "/v1/dids/{did}": {"get": _op("Resolve a DID document (did:key offline; did:web from cache unless enabled)",
                                      params=[_path_param("did")])},
        "/v1/trust-roots": {"post": _op("Add/remove a root DID whose delegation chains an environment accepts",
                                        body="TrustRootInput", errors=write_errors)},
        "/v1/delegations": {"post": _op("Sign an attenuated delegation with a service-held key (local dev)",
                                        body="DelegateInput", errors=write_errors)},
        "/v1/delegations/verify": {"post": _op("Verify a delegation chain (pure; same as the offline verifier)",
                                               body="ChainVerifyInput", errors=write_errors)},
        "/v1/revocations": {
            "get": _op("Revocation list (every record independently signed)", params=[_query("environment", True)],
                       response=_ref("RevocationList")),
            "post": _op("Record a signed revocation (or sign one with a service-held key)", body="RevocationInput",
                        errors=write_errors),
        },
        "/v1/invocations/evaluate": {"post": _op(
            "Verify an invocation and its delegation chain, apply policy, record a v2 receipt; returns an "
            "offline-verifiable bundle. Never executes.", body="InvocationEvaluateInput", errors=write_errors)},
        "/v1/bundles/verify": {"post": _op("Verify a decision bundle back to a root DID (pure; offline verifier)",
                                           body="BundleVerifyInput", errors=write_errors)},
        "/v1/ledger/v2": {"get": _op("Export the v2 (DID) receipt chain for offline verification",
                                     params=[_query("environment", True)])},
    }
    for path, item in paths.items():
        if path != "/v1/health" and path.startswith("/v1/"):
            for operation in item.values():
                operation["responses"].setdefault("421", {"$ref": "#/components/responses/E421"})
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Autheo Agent Environment local trust API",
            "version": __version__,
            "description": (
                "Loopback-only local reference API. Decisions are simulations recorded as signed, "
                "hash-chained receipts; nothing is executed and no wallet or payment is involved. "
                "v1 signature rules: docs/SPEC-SIGNATURES.md. v2 DID identities, delegation chains, "
                "revocation and offline verification: docs/SPEC-DID.md."
            ),
            "license": {"name": "MIT"},
        },
        "servers": [{"url": "http://127.0.0.1:8780", "description": "Default loopback bind"}],
        "security": [{"bearer": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer",
                                           "description": "Token from <state-dir>/api-token"}},
            "schemas": schemas,
            "responses": responses,
        },
    }


def render() -> str:
    return json.dumps(build_openapi(), indent=2, sort_keys=True) + "\n"


def write(path: Path) -> None:
    Path(path).write_text(render(), encoding="utf-8")
