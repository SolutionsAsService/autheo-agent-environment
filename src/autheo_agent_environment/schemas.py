"""Export the versioned JSON Schemas (draft 2020-12) in schemas/ from the strict models.

The committed files are checked for drift by tests and CI, so the models remain
the single source of truth while non-Python consumers get stable JSON Schemas.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from .models import (
    Checkpoint,
    Decision,
    Handoff,
    LedgerEntry,
    Mandate,
    OutcomeReport,
    Passport,
    ReceiptBody,
    Request,
    StrictModel,
)
from .models_v2 import (
    Bundle,
    Capability,
    DataIntegrityProof,
    Delegation,
    DidKeyDocument,
    Invocation,
    LedgerExportV2,
    ReceiptV2,
    Revocation,
    RevocationList,
)
from .policy import PolicyDocument

SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


class JwsHeader(StrictModel):
    """Protected header of every Autheo compact JWS."""

    alg: Literal["EdDSA"]
    typ: Literal[
        "autheo-passport+jwt",
        "autheo-mandate+jwt",
        "autheo-request+jwt",
        "autheo-receipt+jwt",
        "autheo-handoff+jwt",
        "autheo-trust-snapshot+jwt",
        "autheo-outcome+jwt",
    ]
    kid: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class JwsClaims(StrictModel):
    """Claim set of every Autheo compact JWS; "body" is the kind-specific document."""

    iss: Annotated[str, StringConstraints(min_length=1, max_length=96)]
    sub: Annotated[str, StringConstraints(min_length=1, max_length=96)]
    aud: Annotated[str, StringConstraints(min_length=1, max_length=96)]
    iat: Annotated[int, Field(strict=True, ge=0)]
    nbf: Annotated[int, Field(strict=True, ge=0)]
    exp: Annotated[int, Field(strict=True, ge=1)]
    jti: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    body: dict


SCHEMAS = {
    "jws-header": (JwsHeader, "Protected header of an Autheo compact JWS (RFC 7515, EdDSA/Ed25519)"),
    "jws-claims": (JwsClaims, "Claim set shared by all Autheo signed documents"),
    "passport": (Passport, "Body of autheo-passport+jwt: issuer-asserted agent identity and key binding"),
    "mandate": (Mandate, "Body of autheo-mandate+jwt: scoped, budgeted delegation"),
    "request": (Request, "Body of autheo-request+jwt: agent-signed proposal of one action"),
    "decision": (Decision, "Policy decision point result with explanation (not a capability)"),
    "receipt": (ReceiptBody, "Body of autheo-receipt+jwt: hash-linked signed ledger record"),
    "ledger-entry": (LedgerEntry, "Stored ledger row: sequence, request id, receipt JWS, chain hash"),
    "checkpoint": (Checkpoint, "Task checkpoint reference carried by a handoff"),
    "handoff": (Handoff, "Body of autheo-handoff+jwt: destination-bound checkpoint envelope"),
    "outcome": (OutcomeReport, "Body of autheo-outcome+jwt: executor-reported outcome claim"),
    "policy": (PolicyDocument, "Declarative policy document (operator configuration)"),
}


SCHEMAS_V2 = {
    "proof": (DataIntegrityProof, "Autheo profile of a W3C Data Integrity proof (eddsa-jcs-2022, single proof)"),
    "capability": (Capability, "What a delegation grants; children may only narrow it"),
    "delegation": (Delegation, "W3C VC 2.0 delegation credential from one DID to another (proof: capabilityDelegation)"),
    "invocation": (Invocation, "Invoker-signed request embedding its delegation chain (proof: capabilityInvocation)"),
    "revocation": (Revocation, "Signed revocation of a delegation and everything below it"),
    "revocation-list": (RevocationList, "Unsigned list of independently signed revocation records"),
    "receipt": (ReceiptV2, "Environment-signed, hash-linked v2 decision/revocation receipt"),
    "bundle": (Bundle, "Offline verification bundle: receipt + invocation (with chain) + revocations"),
    "ledger-export": (LedgerExportV2, "Export of an environment's v2 receipt chain"),
    "did-key-document": (DidKeyDocument, "DID document generated for a did:key (Multikey form)"),
}


def schema_id(name: str, version: int = 1) -> str:
    # A URN, deliberately not a URL: no hosted schema registry exists.
    return f"urn:autheo:schema:{name}:v{version}"


def build_schema(name: str, version: int = 1) -> dict:
    model, description = (SCHEMAS if version == 1 else SCHEMAS_V2)[name]
    schema = model.model_json_schema(mode="validation", by_alias=True)
    schema.pop("description", None)
    return {
        "$schema": SCHEMA_DIALECT,
        "$id": schema_id(name, version),
        "title": f"autheo.{name}/v{version}",
        "description": description,
        **schema,
    }


def _files():
    for name in SCHEMAS:
        yield name, 1, f"{name}.v1.schema.json"
    for name in SCHEMAS_V2:
        yield name, 2, f"{name}.v2.schema.json"


def render(schema: dict) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def export(directory: Path) -> list[Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, version, file_name in _files():
        path = directory / file_name
        path.write_text(render(build_schema(name, version)), encoding="utf-8")
        written.append(path)
    return written


def check(directory: Path) -> list[str]:
    """Return the names of schema files that are missing or differ from the models."""
    directory = Path(directory)
    stale = []
    for name, version, file_name in _files():
        path = directory / file_name
        if not path.is_file() or path.read_text(encoding="utf-8") != render(build_schema(name, version)):
            stale.append(path.name)
    return stale
