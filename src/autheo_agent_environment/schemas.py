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


def schema_id(name: str) -> str:
    # A URN, deliberately not a URL: no hosted schema registry exists.
    return f"urn:autheo:schema:{name}:v1"


def build_schema(name: str) -> dict:
    model, description = SCHEMAS[name]
    schema = model.model_json_schema(mode="validation")
    schema.pop("description", None)
    return {
        "$schema": SCHEMA_DIALECT,
        "$id": schema_id(name),
        "title": f"autheo.{name}/v1",
        "description": description,
        **schema,
    }


def render(schema: dict) -> str:
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def export(directory: Path) -> list[Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name in SCHEMAS:
        path = directory / f"{name}.v1.schema.json"
        path.write_text(render(build_schema(name)), encoding="utf-8")
        written.append(path)
    return written


def check(directory: Path) -> list[str]:
    """Return the names of schema files that are missing or differ from the models."""
    directory = Path(directory)
    stale = []
    for name in SCHEMAS:
        path = directory / f"{name}.v1.schema.json"
        if not path.is_file() or path.read_text(encoding="utf-8") != render(build_schema(name)):
            stale.append(path.name)
    return stale
