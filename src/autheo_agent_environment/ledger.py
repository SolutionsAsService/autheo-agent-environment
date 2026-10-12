"""Persistent ledger verification and anchoring helpers.

The ledger is the SQLite "events" table written by Environment: one signed
autheo-receipt+jwt per row, linked by chain_hash = sha256(previous_hash || token).
Persistent ledgers created through the state directory also install SQLite
triggers that reject UPDATE/DELETE. Triggers stop accidental edits only; anyone
with write access to the file can drop them, so verification - not the triggers -
is the tamper-detection mechanism, and only an externally stored head can detect
a truncated tail or a wholesale replacement.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import jwt
from pydantic import ValidationError

from .canonical import ZERO_HASH, chain_hash, digest
from .models import RECEIPT_KINDS, ReceiptBody
from .signing import public_pem, verify

MAX_PROBLEMS = 50
EXPECTED_TRIGGERS = {
    "events_append_only_update",
    "events_append_only_delete",
    "revoked_append_only_update",
    "revoked_append_only_delete",
}


def _connect_read_only(path: Path):
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Ledger database not found: {path}")
    return sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True, timeout=10)


def verify_rows(rows, public_key, issuer: str, environment: str, kid: str) -> dict:
    """Verify (sequence, request_id, token, chain_hash) rows; never raises on bad data."""
    problems: list[dict] = []
    previous, count, request_ids = ZERO_HASH, 0, set()

    def problem(sequence, reason):
        if len(problems) < MAX_PROBLEMS:
            problems.append({"sequence": sequence, "problem": reason})

    for index, (sequence, request_id, token, stored_hash) in enumerate(rows, 1):
        count = index
        if sequence != index:
            problem(sequence, "sequence_gap_or_reorder")
        try:
            claims = verify(token, "receipt", public_key, issuer, environment, kid, historical=True)
        except (jwt.InvalidTokenError, ValueError) as error:
            problem(sequence, f"signature_or_claims_invalid:{type(error).__name__}")
            claims = None
        try:
            recomputed = chain_hash(previous, token)
        except (ValueError, UnicodeEncodeError):
            recomputed = None
            problem(sequence, "unhashable_token")
        if recomputed is not None and recomputed != stored_hash:
            problem(sequence, "chain_hash_mismatch")
        if claims is not None:
            body = claims["body"]
            if body.get("sequence") != sequence:
                problem(sequence, "body_sequence_mismatch")
            if body.get("previous_hash") != previous:
                problem(sequence, "previous_hash_mismatch")
            if body.get("request_id") != request_id:
                problem(sequence, "request_id_mismatch")
            if body.get("executed") is not False:
                problem(sequence, "executed_flag_invalid")
            if body.get("kind") not in RECEIPT_KINDS:
                problem(sequence, "unknown_kind")
            if body.get("request_id") in request_ids:
                problem(sequence, "duplicate_request_id")
            request_ids.add(body.get("request_id"))
            if "schema_version" in body:
                try:
                    ReceiptBody.model_validate(body)
                except ValidationError:
                    problem(sequence, "receipt_schema_invalid")
        # Continue from the recomputed link so later rows are judged on their own merit.
        previous = recomputed or stored_hash
    return {
        "valid": not problems,
        "count": count,
        "head": previous,
        "first_invalid_sequence": problems[0]["sequence"] if problems else None,
        "problems": problems,
    }


def verify_database(
    path: Path, public_key, issuer: str, environment: str, kid: str, expected_head: str | None = None
) -> dict:
    """Full verification report for a ledger database (read-only connection)."""
    with closing(_connect_read_only(path)) as db:
        metadata = dict(db.execute("SELECT name, value FROM metadata"))
        rows = list(db.execute("SELECT sequence, request_id, token, chain_hash FROM events ORDER BY sequence"))
        triggers = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
    report = verify_rows(rows, public_key, issuer, environment, kid)
    expected_metadata = {
        "environment": environment,
        "issuer": issuer,
        "key": digest(public_pem(public_key)),
    }
    if metadata != expected_metadata:
        report["problems"].insert(0, {"sequence": 0, "problem": "ledger_identity_mismatch"})
        report["valid"] = False
        report["first_invalid_sequence"] = 0
    report.update(
        environment=environment,
        issuer=issuer,
        kid=kid,
        append_only_triggers=EXPECTED_TRIGGERS <= triggers,
        expected_head=expected_head,
        expected_head_matched=None if expected_head is None else report["head"] == expected_head,
        tamper_evident=True,
        immutable=False,
        externally_anchored=False,
        actual_actions_proven=False,
    )
    if expected_head is not None and report["head"] != expected_head:
        report["valid"] = False
        report["problems"].append({"sequence": report["count"], "problem": "head_differs_from_anchor"})
    return report


def anchor_record(report: dict) -> dict:
    """A head record to store OUTSIDE the ledger host (ticket, git, another machine)."""
    return {
        "type": "autheo-ledger-anchor/v1",
        "environment": report["environment"],
        "issuer": report["issuer"],
        "kid": report["kid"],
        "count": report["count"],
        "head": report["head"],
        "recorded_at": int(time.time()),
        "note": "Only an anchor stored independently of the ledger host can detect truncation or replacement.",
    }


def read_anchor(path: Path) -> str:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("type") != "autheo-ledger-anchor/v1":
        raise ValueError("Not an autheo ledger anchor file")
    return data["head"]
