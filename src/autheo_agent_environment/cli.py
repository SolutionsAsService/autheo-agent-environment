"""Command-line interface: python -m autheo_agent_environment <command> ...

Every command prints JSON on stdout. Errors print {"error": ...} on stderr and
exit non-zero; "ledger verify" also exits 1 when the ledger fails verification.
State lives in --state-dir (default $AUTHEO_STATE_DIR or ./.autheo-state).
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path

import jwt
from pydantic import ValidationError

from .cli_did import add_did_parser, run_did
from .data_integrity import ProofError
from .did import DidError
from .errors import ConflictError, NotFoundError
from .models import SCOPES


def _print(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=False))


def _read_text(path: str, limit: int = 1_000_000) -> str:
    if path == "-":
        return sys.stdin.read(limit + 1)[:limit].strip()
    file = Path(path)
    if file.stat().st_size > limit:
        raise ValueError("Input exceeds size limit")
    return file.read_text(encoding="utf-8").strip()


def _service(args):
    from .service import TrustService
    from .state import StateDir

    return TrustService(StateDir(args.state_dir))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m autheo_agent_environment", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--state-dir", type=Path,
                        default=Path(os.environ.get("AUTHEO_STATE_DIR", ".autheo-state")))
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a local state directory (keys, policy, ledgers)")
    init.add_argument("--issuer", default="autheo-local-authority")
    init.add_argument("--environment", action="append", dest="environments")
    init.add_argument("--policy", type=Path, help="initial policy file (YAML/JSON)")

    commands.add_parser("info", help="issuer, key id, environments, policy digest")

    identity = commands.add_parser("identity").add_subparsers(dest="action", required=True)
    issue = identity.add_parser("issue", help="issue an agent passport")
    issue.add_argument("--agent-id", required=True)
    issue.add_argument("--owner-id", required=True)
    issue.add_argument("--environment", action="append", dest="environments", required=True)
    key = issue.add_mutually_exclusive_group(required=True)
    key.add_argument("--public-key-file", help="agent-held Ed25519 public key (SPKI PEM)")
    key.add_argument("--generate-key", action="store_true", help="local-dev custody: key stored in state dir")
    issue.add_argument("--ttl", type=int, default=86400)
    identity.add_parser("show").add_argument("agent_id")
    revoke_identity = identity.add_parser("revoke")
    revoke_identity.add_argument("agent_id")
    revoke_identity.add_argument("--reason", default="operator_revoked")

    mandate = commands.add_parser("mandate").add_subparsers(dest="action", required=True)
    grant = mandate.add_parser("grant", help="grant a scoped, budgeted mandate")
    grant.add_argument("--agent-id", required=True)
    grant.add_argument("--environment", required=True)
    grant.add_argument("--scope", action="append", dest="scopes", required=True, choices=SCOPES)
    grant.add_argument("--resource", action="append", dest="resources", required=True)
    grant.add_argument("--tool", action="append", dest="tools", default=[])
    grant.add_argument("--destination", action="append", dest="destinations", default=[])
    grant.add_argument("--per-action", type=int, required=True)
    grant.add_argument("--total", type=int, required=True)
    grant.add_argument("--threshold", type=int, required=True, help="amounts above this escalate")
    grant.add_argument("--ttl", type=int, default=3600)
    mandate.add_parser("show").add_argument("mandate_id")
    mandate.add_parser("list").add_argument("--agent-id")
    revoke = mandate.add_parser("revoke")
    revoke.add_argument("mandate_id")
    revoke.add_argument("--reason", default="operator_revoked")

    evaluate = commands.add_parser("evaluate", help="evaluate one action (records a receipt, executes nothing)")
    evaluate.add_argument("--request-token-file", help="agent-signed autheo-request+jwt ('-' for stdin)")
    evaluate.add_argument("--agent-id")
    evaluate.add_argument("--mandate-id")
    evaluate.add_argument("--action", choices=SCOPES)
    evaluate.add_argument("--resource")
    evaluate.add_argument("--tool")
    evaluate.add_argument("--amount", type=int, default=0)
    evaluate.add_argument("--request-id")

    outcome = commands.add_parser("outcome", help="record an executor-reported outcome for an allowed decision")
    outcome.add_argument("--environment", required=True)
    outcome.add_argument("--request-id", required=True)
    outcome.add_argument("--status", required=True, choices=["succeeded", "failed", "unknown"])
    outcome.add_argument("--detail-sha256")
    outcome.add_argument("--report-token-file")

    receipt = commands.add_parser("receipt").add_subparsers(dest="action", required=True)
    receipt.add_parser("verify").add_argument("token_file", help="receipt JWS file or '-'")
    listing = receipt.add_parser("list")
    listing.add_argument("--environment", required=True)
    listing.add_argument("--limit", type=int, default=20)
    listing.add_argument("--agent-id")

    ledger = commands.add_parser("ledger").add_subparsers(dest="action", required=True)
    verify = ledger.add_parser("verify", help="verify signatures, links, identity, triggers")
    verify.add_argument("--environment", required=True)
    head = verify.add_mutually_exclusive_group()
    head.add_argument("--expected-head")
    head.add_argument("--anchor", type=Path, help="anchor file written by 'ledger anchor'")
    anchor = ledger.add_parser("anchor", help="write the current head for storage elsewhere")
    anchor.add_argument("--environment", required=True)
    anchor.add_argument("--output", type=Path, required=True)
    export = ledger.add_parser("export", help="export a receipt archive for offline audit")
    export.add_argument("--environment", required=True)
    export.add_argument("--output", type=Path, required=True)

    checkpoint = commands.add_parser("checkpoint", help="export a signed checkpoint to another environment")
    checkpoint.add_argument("--agent-id", required=True)
    checkpoint.add_argument("--mandate-id", required=True)
    checkpoint.add_argument("--destination", required=True)
    checkpoint.add_argument("--scope", action="append", dest="scopes", required=True, choices=SCOPES)
    checkpoint.add_argument("--task-id", required=True)
    checkpoint.add_argument("--step", required=True, choices=["planned", "inspected", "awaiting_review"])
    checkpoint.add_argument("--artifact-sha256", required=True)
    checkpoint.add_argument("--output", type=Path, help="also write the handoff token to this file")

    handoff = commands.add_parser("handoff").add_subparsers(dest="action", required=True)
    accept = handoff.add_parser("accept")
    accept.add_argument("--token-file", required=True)
    accept.add_argument("--allowed-scope", action="append", dest="allowed_scopes", required=True, choices=SCOPES)

    policy = commands.add_parser("policy").add_subparsers(dest="action", required=True)
    policy.add_parser("show")
    policy.add_parser("validate").add_argument("file", type=Path)

    for name, help_text in [("schema", "JSON Schemas"), ("vectors", "cross-language test vectors"),
                            ("openapi", "OpenAPI document")]:
        group = commands.add_parser(name, help=help_text).add_subparsers(dest="action", required=True)
        group.add_parser("write" if name == "openapi" else ("export" if name == "schema" else "generate")
                         ).add_argument("path", type=Path)
        group.add_parser("check").add_argument("path", type=Path)

    add_did_parser(commands)

    serve = commands.add_parser("serve", help="run the loopback HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8780)
    serve.add_argument("--allow-remote", action="store_true", help="DANGEROUS: no TLS; bind non-loopback")

    demo = commands.add_parser("demo", help="ephemeral end-to-end walkthrough (no network)")
    demo.add_argument("--output", type=Path, default=Path("demo-output"))
    commands.add_parser("web", help="loopback browser demo backed by the API").add_argument(
        "--port", type=int, default=8765)
    return parser


def run(args) -> int:  # noqa: C901 - flat command dispatch is clearer than indirection here
    from . import service as svc

    command, action = args.command, getattr(args, "action", None)
    if command == "did":
        return run_did(args, lambda: _service(args), _print)
    if command == "init":
        from .state import StateDir

        policy_text = args.policy.read_text(encoding="utf-8") if args.policy else None
        state = StateDir.init(args.state_dir, args.issuer, args.environments, policy_text)
        _print({"state_dir": str(state.root.resolve()), "issuer": state.authority.issuer,
                "kid": state.authority.kid, "environments": state.environments,
                "api_token_file": str((state.root / "api-token").resolve()),
                "custody": "local development file key - not production custody"})
        return 0
    if command == "policy" and action == "validate":
        from .policy import load_policy

        document = load_policy(args.file)
        _print({"valid": True, "policy_id": document.policy_id, "policy_digest": document.digest})
        return 0
    if command in {"schema", "vectors", "openapi"}:
        return _artifacts(command, action, args.path)
    if command == "demo":
        from .demo import run as run_demo

        _print(run_demo(args.output))
        return 0
    if command == "web":
        from .webapp import main as web_main

        web_main(["--port", str(args.port)])
        return 0
    if command == "serve":
        from .api import serve

        serve(args.state_dir, args.host, args.port, args.allow_remote)
        return 0

    service = _service(args)
    if command == "info":
        result = service.info()
    elif command == "policy":
        result = service.policy_document()
    elif command == "identity":
        if action == "issue":
            public_key = _read_text(args.public_key_file, 4096) + "\n" if args.public_key_file else None
            result = service.issue_identity(svc.IdentityIssueInput(
                agent_id=args.agent_id, owner_id=args.owner_id, environments=args.environments,
                public_key=public_key, generate_key=args.generate_key, ttl_seconds=args.ttl))
        elif action == "show":
            result = service.get_identity(args.agent_id)
        else:
            result = service.revoke_identity(args.agent_id, svc.RevokeInput(reason=args.reason))
    elif command == "mandate":
        if action == "grant":
            result = service.grant_mandate(svc.MandateGrantInput(
                agent_id=args.agent_id, environment=args.environment, scopes=args.scopes,
                resources=args.resources, tools=args.tools, destinations=args.destinations,
                per_action_minor=args.per_action, total_budget_minor=args.total,
                approval_threshold_minor=args.threshold, ttl_seconds=args.ttl))
        elif action == "show":
            result = service.mandate_status(args.mandate_id)
        elif action == "list":
            result = {"mandates": [{k: v for k, v in row.items() if k != "mandate_token"}
                                   for row in service.state.list_mandates(args.agent_id)]}
        else:
            result = service.revoke_mandate(args.mandate_id, svc.RevokeInput(reason=args.reason))
    elif command == "evaluate":
        if args.request_token_file:
            data = svc.EvaluateInput(request_token=_read_text(args.request_token_file))
        else:
            missing = [n for n in ("agent_id", "mandate_id", "action", "resource") if not getattr(args, n)]
            if missing:
                raise ValueError("Missing --" + ", --".join(m.replace("_", "-") for m in missing))
            data = svc.EvaluateInput(request=svc.ActionInput(
                agent_id=args.agent_id, mandate_id=args.mandate_id, action=args.action, resource=args.resource,
                tool=args.tool, amount_minor=args.amount, request_id=args.request_id))
        result = service.evaluate(data)
    elif command == "outcome":
        token = _read_text(args.report_token_file) if args.report_token_file else None
        result = service.record_outcome(svc.OutcomeInput(
            environment=args.environment, request_id=args.request_id, status=args.status,
            detail_sha256=args.detail_sha256, report_token=token))
    elif command == "receipt":
        if action == "verify":
            result = service.verify_receipt(svc.VerifyReceiptInput(token=_read_text(args.token_file)))
        else:
            result = service.receipts(args.environment, args.limit, args.agent_id)
    elif command == "ledger":
        from .ledger import anchor_record, read_anchor

        if action == "verify":
            expected = read_anchor(args.anchor) if args.anchor else args.expected_head
            result = service.verify_ledger(svc.LedgerVerifyInput(environment=args.environment,
                                                                 expected_head=expected))
            _print(result)
            return 0 if result["valid"] else 1
        report = service.verify_ledger(svc.LedgerVerifyInput(environment=args.environment))
        if not report["valid"]:
            _print(report)
            return 1
        if action == "anchor":
            record = anchor_record(report)
            args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
            result = record
        else:
            service.environment(args.environment).export_audit(args.output)
            result = {"archive": str(args.output), "count": report["count"], "head": report["head"],
                      "verify_with": "python -m autheo_agent_environment.audit <archive> --public-key "
                                     f"{service.state.public_key_path} --issuer {service.authority.issuer} "
                                     f"--environment {args.environment} --kid {service.authority.kid}"}
    elif command == "checkpoint":
        from .models import Checkpoint

        result = service.checkpoint(svc.CheckpointInput(
            agent_id=args.agent_id, mandate_id=args.mandate_id, destination=args.destination, scopes=args.scopes,
            checkpoint=Checkpoint(task_id=args.task_id, step=args.step, artifact_sha256=args.artifact_sha256)))
        if args.output:
            args.output.write_text(result["handoff_token"] + "\n", encoding="utf-8")
    elif command == "handoff":
        result = service.accept_handoff(svc.HandoffAcceptInput(
            handoff_token=_read_text(args.token_file), allowed_scopes=args.allowed_scopes))
    else:  # pragma: no cover - argparse enforces the command set
        raise ValueError("Unknown command")
    _print(result)
    return 0


def _artifacts(command: str, action: str, path: Path) -> int:
    if command == "schema":
        from . import schemas

        if action == "export":
            _print({"written": [str(p) for p in schemas.export(path)]})
            return 0
        stale = schemas.check(path)
        _print({"up_to_date": not stale, "stale": stale})
        return 0 if not stale else 1
    module = importlib.import_module(f"{__package__}.{command}")
    if action in {"generate", "write"}:
        module.write(path)
        _print({"written": str(path)})
        return 0
    current = path.read_text(encoding="utf-8") if path.is_file() else None
    up_to_date = current == module.render()
    _print({"up_to_date": up_to_date, "path": str(path)})
    return 0 if up_to_date else 1


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (NotFoundError, FileNotFoundError) as error:
        code, message = "not_found", str(error)
    except ConflictError as error:
        code, message = "conflict", str(error)
    except FileExistsError as error:
        code, message = "exists", str(error)
    except ValidationError as error:
        code = "schema_validation_failed"
        message = ", ".join(sorted({".".join(str(p) for p in e["loc"]) or e["msg"] for e in error.errors()}))
    except ProofError as error:
        code, message = "proof_invalid", str(error)
    except DidError as error:
        code, message = "did_invalid", str(error)
    except jwt.InvalidTokenError as error:
        code, message = "token_invalid", type(error).__name__
    except ValueError as error:
        code, message = "rejected", str(error)
    print(json.dumps({"error": code, "detail": message[:500]}), file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
