"""Offline verifier for Autheo v2: delegation chains, invocations, decision bundles, ledger exports.

Needs only the documents and DIDs: did:key resolves locally, did:web only from a
local cache directory (this module never enables network resolution). No state
directory, service or API is involved.

    python -m autheo_agent_environment.verifier bundle bundle.json --root did:key:z6Mk...
    python -m autheo_agent_environment.verifier chain chain.json --root did:key:z6Mk... --at 1790000020
    python -m autheo_agent_environment.verifier ledger ledger-export.json --issuer did:key:z6Mk...

Exit status: 0 valid, 1 verification failed, 2 usage/input error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from pydantic import ValidationError

from .canonical import ZERO_HASH, is_hex64
from .data_integrity import ProofError, parse_time, verify_proof
from .delegation import (
    CLOCK_SKEW_SECONDS,
    capability_problems,
    document_digest,
    verify_chain,
    verify_invocation,
)
from .did import Resolver
from .jcs import canonicalize
from .models_v2 import Bundle, ReceiptV2

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_PROBLEMS = 50


def v2_chain_hash(previous_hash: str, receipt: dict) -> str:
    """v2 ledger link: lowercase_hex(SHA-256(ascii(previous_hash) || JCS(signed receipt)))."""
    if not is_hex64(previous_hash):
        raise ValueError("previous hash must be 64 lowercase hex characters")
    return hashlib.sha256(previous_hash.encode("ascii") + canonicalize(receipt)).hexdigest()


def verify_receipt(receipt: dict, resolver: Resolver, issuer: str | None = None) -> ReceiptV2:
    """Verify one v2 receipt's structure and proof (raises ProofError)."""
    try:
        model = ReceiptV2.model_validate(receipt)
    except ValidationError as error:
        raise ProofError("malformed", "receipt does not match autheo.receipt/v2") from error
    proof = verify_proof(receipt, resolver, "assertionMethod")
    if proof.controller != model.issuer:
        raise ProofError("bad_signature", "receipt proof is not by its issuer")
    if issuer is not None and model.issuer != issuer:
        raise ProofError("untrusted_issuer", f"receipt issued by {model.issuer}, expected {issuer}")
    return model


def verify_receipts(receipts, *, resolver: Resolver, issuer: str, environment: str | None = None,
                    expected_head: str | None = None) -> dict:
    """Verify an ordered v2 receipt chain; never raises on bad data."""
    problems: list[dict] = []
    previous, ids = ZERO_HASH, set()

    def problem(sequence, reason):
        if len(problems) < MAX_PROBLEMS:
            problems.append({"sequence": sequence, "problem": reason})

    receipts = receipts if isinstance(receipts, list) else []
    for index, receipt in enumerate(receipts, 1):
        try:
            model = verify_receipt(receipt, resolver, issuer)
        except ProofError as error:
            problem(index, f"receipt_invalid:{error.code}")
            try:
                previous = v2_chain_hash(previous, receipt)
            except ValueError:
                pass
            continue
        if model.sequence != index:
            problem(index, "sequence_gap_or_reorder")
        if model.previous_hash != previous:
            problem(index, "previous_hash_mismatch")
        if environment is not None and model.environment != environment:
            problem(index, "wrong_environment")
        if model.id in ids:
            problem(index, "duplicate_receipt_id")
        ids.add(model.id)
        previous = v2_chain_hash(previous, receipt)
    head = previous
    anchor_ok = None if expected_head is None else head == expected_head
    if anchor_ok is False:
        problem(len(receipts), "head_differs_from_anchor")
    return {
        "valid": not problems,
        "count": len(receipts),
        "head": head,
        "issuer": issuer,
        "first_invalid_sequence": problems[0]["sequence"] if problems else None,
        "problems": problems,
        "anchor_matches": anchor_ok,
        "externally_anchored": False,
    }


def verify_bundle(bundle: dict, *, resolver: Resolver, trusted_roots=None, environment_did: str | None = None,
                  extra_revocations=(), skew: int = CLOCK_SKEW_SECONDS) -> dict:
    """Verify a decision bundle and its whole delegation chain as of the receipt's recorded_at."""
    report = {"valid": False, "problems": [], "network_used": False, "root_pinned": trusted_roots is not None,
              "environment_pinned": environment_did is not None}
    problems = report["problems"]
    try:
        Bundle.model_validate(bundle)
    except ValidationError as error:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in error.errors()})[:8]
        problems.append("malformed_bundle: " + ", ".join(fields))
        return report
    receipt_raw, invocation_raw = bundle["receipt"], bundle["invocation"]
    try:
        receipt = verify_receipt(receipt_raw, resolver, environment_did)
    except ProofError as error:
        problems.append(f"receipt_invalid:{error.code}")
        return report
    report.update(decision=receipt.decision, reasons=receipt.reasons, environment=receipt.environment,
                  issuer=receipt.issuer, recorded_at=receipt.recorded_at, sequence=receipt.sequence,
                  executed=False)
    if receipt.kind != "decision":
        problems.append("receipt_is_not_a_decision")
        return report
    if document_digest(invocation_raw) != receipt.document_digest:
        problems.append("invocation_digest_mismatch")
        return report
    revocations = list(bundle.get("revocations", [])) + list(extra_revocations)
    try:
        result = verify_invocation(invocation_raw, resolver=resolver, at=receipt.recorded_at,
                                   trusted_roots=trusted_roots, revocations=revocations, skew=skew)
    except ProofError as error:
        problems.append(f"invocation_invalid:{error.code}")
        return report
    invocation, chain = result.invocation, result.chain
    report.update(invoker=invocation.invoker, root=chain.root, request_id=invocation.id,
                  chain=chain.to_dict())
    bindings = {
        "request_id": (receipt.request_id, invocation.id),
        "invoker": (receipt.invoker, invocation.invoker),
        "environment": (receipt.environment, invocation.environment),
        "action": (receipt.action, invocation.action),
        "resource": (receipt.resource, invocation.resource),
        "tool": (receipt.tool, invocation.tool),
        "amount_minor": (receipt.amount_minor, invocation.amount_minor),
        "asset": (receipt.asset or "DEMO", invocation.asset),
        "root": (receipt.root, chain.root),
        "chain": ([link.model_dump() for link in receipt.chain],
                  [{k: link[k] for k in ("id", "digest", "issuer", "subject")} for link in chain.links]),
    }
    for name, (recorded, actual) in bindings.items():
        if recorded != actual:
            problems.append(f"receipt_binding_mismatch:{name}")
    if not chain.authentic:
        problems.append("delegation_chain_not_authentic")
    request_problems = []
    if chain.capability is not None:
        request_problems = [code for code, _ in capability_problems(
            chain.capability, environment=invocation.environment, action=invocation.action,
            resource=invocation.resource, tool=invocation.tool, amount_minor=invocation.amount_minor,
            asset=invocation.asset)]
    authorized = chain.valid and not request_problems
    report["authorized_by_chain"] = authorized
    report["request_problems"] = request_problems
    if receipt.decision == "allow" and not authorized:
        problems.append("allow_not_supported_by_chain")
    report["valid"] = not problems
    report["verdict"] = (f"{receipt.decision}_verified" if report["valid"] else "invalid")
    return report


# ---------------------------------------------------------------------- CLI
def _load(path: str):
    data = sys.stdin.read(MAX_INPUT_BYTES + 1) if path == "-" else Path(path).read_text(encoding="utf-8")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input too large")
    return json.loads(data)


def load_revocations(paths) -> list[dict]:
    records = []
    for path in paths or []:
        data = _load(path)
        if isinstance(data, dict) and data.get("schema_version") == "autheo.revocation-list/v2":
            records.extend(data.get("records", []))
        elif isinstance(data, list):
            records.extend(data)
        else:
            records.append(data)
    return records


def chain_from(data) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if data.get("type") == "AutheoInvocation":
            return data.get("capability", [])
        if "chain" in data and isinstance(data["chain"], list):
            return data["chain"]
        if "invocation" in data and isinstance(data["invocation"], dict):
            return data["invocation"].get("capability", [])
        return [data]
    return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m autheo_agent_environment.verifier", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in [("bundle", "decision bundle (receipt + invocation + chain)"),
                            ("chain", "delegation chain (list, single credential, invocation or bundle)"),
                            ("invocation", "signed invocation, checked now (or --at)")]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("file", help="JSON file or '-'")
        roots = command.add_mutually_exclusive_group(required=True)
        roots.add_argument("--root", action="append", dest="roots", help="trusted root DID (repeatable)")
        roots.add_argument("--any-root", action="store_true", help="accept any root DID (reported, not pinned)")
        command.add_argument("--revocations", action="append", help="revocation record/list file (repeatable)")
        command.add_argument("--did-web-cache", type=Path, help="directory of cached did:web documents")
        command.add_argument("--skew", type=int, default=CLOCK_SKEW_SECONDS)
        if name == "bundle":
            command.add_argument("--environment-did", help="expected receipt issuer DID")
        else:
            command.add_argument("--at", help="verification time: epoch seconds or YYYY-MM-DDTHH:MM:SSZ")
    ledger = commands.add_parser("ledger", help="v2 ledger export (autheo.ledger-export/v2)")
    ledger.add_argument("file")
    ledger.add_argument("--issuer", help="expected environment DID (trust anchor)")
    ledger.add_argument("--expected-head", help="independently stored head to detect truncation")
    ledger.add_argument("--did-web-cache", type=Path)
    return parser


def _at(value) -> int:
    if value is None:
        return int(time.time())
    return int(value) if str(value).isdigit() else parse_time(value)


def run(args) -> tuple[int, dict]:
    resolver = Resolver(cache_dir=args.did_web_cache, allow_network=False)
    data = _load(args.file)
    if args.command == "ledger":
        if not isinstance(data, dict):
            raise ValueError("ledger export must be a JSON object")
        issuer = args.issuer or data.get("issuer")
        report = verify_receipts(data.get("receipts"), resolver=resolver, issuer=issuer,
                                 environment=data.get("environment"), expected_head=args.expected_head)
        report["issuer_pinned"] = args.issuer is not None
        if data.get("head") != report["head"]:
            report["valid"] = False
            report["problems"].append({"sequence": None, "problem": "export_head_mismatch"})
        return (0 if report["valid"] else 1), report
    roots = None if args.any_root else args.roots
    revocations = load_revocations(args.revocations)
    if args.command == "bundle":
        report = verify_bundle(data, resolver=resolver, trusted_roots=roots, environment_did=args.environment_did,
                               extra_revocations=revocations, skew=args.skew)
        return (0 if report["valid"] else 1), report
    at = _at(args.at)
    if args.command == "chain":
        report = verify_chain(chain_from(data), resolver=resolver, at=at, trusted_roots=roots,
                              revocations=revocations, skew=args.skew).to_dict()
        report["root_pinned"] = roots is not None
        return (0 if report["valid"] else 1), report
    try:
        result = verify_invocation(data, resolver=resolver, at=at, trusted_roots=roots, revocations=revocations,
                                   skew=args.skew)
    except ProofError as error:
        return 1, {"valid": False, "problems": [f"invocation_invalid:{error.code}"], "detail": str(error)[:300]}
    report = {"valid": result.chain.valid, "invocation_digest": result.digest, "invoker": result.invocation.invoker,
              "chain": result.chain.to_dict(), "root_pinned": roots is not None}
    problems = capability_problems(result.chain.capability, environment=result.invocation.environment,
                                   action=result.invocation.action, resource=result.invocation.resource,
                                   tool=result.invocation.tool, amount_minor=result.invocation.amount_minor,
                                   asset=result.invocation.asset) if result.chain.capability else []
    report["request_problems"] = [code for code, _ in problems]
    report["valid"] = report["valid"] and not problems
    return (0 if report["valid"] else 1), report


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code, report = run(args)
    except (OSError, ValueError) as error:
        print(json.dumps({"error": "input_invalid", "detail": str(error)[:300]}), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
