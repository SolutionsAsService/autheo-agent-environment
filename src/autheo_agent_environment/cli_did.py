"""The "did" command group: permissionless identities, delegation, revocation and verification.

Offline (no state directory, no service, no network):
  did create --out key.json            generate a did:key; private key stays in key.json
  did resolve DID                      DID document (did:web only from --did-web-cache)
  did from-key --public-key-file PEM   v1 public key -> did:key and v1 kid
  did web-cache add DOC --did-web-cache DIR   pin a did:web document for offline use
  did delegate --key K --to DID ...    sign an attenuated delegation (writes a chain file)
  did revoke --key K --chain FILE      sign a revocation record
  did invoke --key K --chain FILE ...  sign an invocation embedding the chain
  did verify bundle|chain|invocation|ledger ...   the offline verifier

Against the local state directory (records receipts):
  did trust --environment E --root DID [--remove]
  did evaluate --invocation FILE [--bundle-out FILE]
  did record-revocation FILE
  did revocations --environment E [--out FILE]
  did ledger export|verify --environment E
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from uuid import uuid4

from .models import SCOPES


def _json(path: str):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path: Path, value, private: bool = False) -> None:
    text = json.dumps(value, indent=2) + "\n"
    if private:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        Path(path).write_text(text, encoding="utf-8")


def _chain(path: str | None) -> list:
    if path is None:
        return []
    from .verifier import chain_from

    return chain_from(_json(path))


def add_did_parser(commands) -> None:
    did = commands.add_parser("did", help="DID identities, delegation chains, revocation, offline verification",
                              description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = did.add_subparsers(dest="action", required=True)

    create = actions.add_parser("create", help="generate a did:key (no registration anywhere)")
    create.add_argument("--out", type=Path, help="write the PRIVATE key file here (created 0600, never overwritten)")
    create.add_argument("--service", action="store_true", help="store the key in the state dir (local-dev custody)")
    create.add_argument("--seed-hex", help=argparse.SUPPRESS)  # deterministic tests only

    resolve = actions.add_parser("resolve", help="resolve a DID document")
    resolve.add_argument("did")
    resolve.add_argument("--did-web-cache", type=Path)
    resolve.add_argument("--allow-network", action="store_true", help="permit HTTPS did:web resolution")
    resolve.add_argument("--encryption-key", action="store_true", help="include the derived X25519 keyAgreement key")

    from_key = actions.add_parser("from-key", help="map a v1 Ed25519 public key (SPKI PEM) to its did:key")
    from_key.add_argument("--public-key-file", required=True)

    cache = actions.add_parser("web-cache", help="manage pinned did:web documents")
    cache.add_argument("cache_action", choices=["add"])
    cache.add_argument("document")
    cache.add_argument("--did-web-cache", type=Path, required=True)

    delegate = actions.add_parser("delegate", help="sign an attenuated delegation to another DID")
    delegate.add_argument("--key", required=True, help="issuer key file (did key JSON or Ed25519 PEM)")
    delegate.add_argument("--to", required=True, help="subject DID")
    delegate.add_argument("--parent", help="chain file (or single delegation) being sub-delegated")
    delegate.add_argument("--environment", action="append", dest="environments", required=True,
                          help="environment id or prefix* pattern")
    delegate.add_argument("--scope", action="append", dest="scopes", required=True, choices=SCOPES)
    delegate.add_argument("--resource", action="append", dest="resources", required=True)
    delegate.add_argument("--tool", action="append", dest="tools", default=[])
    delegate.add_argument("--per-action", type=int, required=True)
    delegate.add_argument("--total", type=int, required=True)
    delegate.add_argument("--threshold", type=int, required=True, help="amounts above this escalate")
    delegate.add_argument("--depth", type=int, default=0, help="how many further delegation levels are allowed")
    delegate.add_argument("--ttl", type=int, default=3600)
    delegate.add_argument("--out", type=Path, help="write the resulting chain (JSON list) here")

    revoke = actions.add_parser("revoke", help="sign a revocation of one link of a chain")
    revoke.add_argument("--key", required=True)
    revoke.add_argument("--chain", required=True, help="chain file or single delegation")
    revoke.add_argument("--index", type=int, help="link to revoke (default: last)")
    revoke.add_argument("--reason", default="revoked")
    revoke.add_argument("--out", type=Path)

    invoke = actions.add_parser("invoke", help="sign an invocation (request) using a delegation chain")
    invoke.add_argument("--key", required=True, help="invoker key: the subject of the leaf delegation")
    invoke.add_argument("--chain", required=True)
    invoke.add_argument("--environment", required=True)
    invoke.add_argument("--action", dest="invoked_action", required=True, choices=SCOPES)
    invoke.add_argument("--resource", required=True)
    invoke.add_argument("--tool")
    invoke.add_argument("--amount", type=int, default=0)
    invoke.add_argument("--request-id")
    invoke.add_argument("--ttl", type=int, default=60)
    invoke.add_argument("--out", type=Path)

    verify = actions.add_parser("verify", help="offline verifier (see python -m autheo_agent_environment.verifier -h)",
                                add_help=False)
    verify.add_argument("rest", nargs=argparse.REMAINDER)

    trust = actions.add_parser("trust", help="trust a root DID for an environment (state dir)")
    trust.add_argument("--environment", required=True)
    trust.add_argument("--root", required=True)
    trust.add_argument("--remove", action="store_true")

    evaluate = actions.add_parser("evaluate", help="evaluate a signed invocation (records a v2 receipt)")
    evaluate.add_argument("--invocation", required=True)
    evaluate.add_argument("--bundle-out", type=Path, help="write the offline verification bundle here")

    record = actions.add_parser("record-revocation", help="record a signed revocation in every environment ledger")
    record.add_argument("file")

    revocations = actions.add_parser("revocations", help="export the revocation list")
    revocations.add_argument("--environment", required=True)
    revocations.add_argument("--out", type=Path)

    ledger = actions.add_parser("ledger", help="v2 receipt chain")
    ledger.add_argument("ledger_action", choices=["export", "verify"])
    ledger.add_argument("--environment", required=True)
    ledger.add_argument("--out", type=Path)
    ledger.add_argument("--expected-head")


def run_did(args, service_factory, emit) -> int:  # noqa: C901 - flat dispatch
    from .delegation import issue_delegation, issue_invocation, issue_revocation
    from .did import DidKey, Resolver, did_key_document, did_key_from_pem, v1_kid_for_did_key

    action = args.action
    if action == "verify":
        from .verifier import main as verifier_main

        return verifier_main(args.rest)
    if action == "create":
        if args.service:
            from .service_did import DidCreateInput

            emit(service_factory().create_did(DidCreateInput()))
            return 0
        if args.out is None:
            raise ValueError("--out is required (the private key is written only to a file)")
        key = DidKey.from_seed(bytes.fromhex(args.seed_hex)) if args.seed_hex else DidKey.generate()
        _write_json(args.out, key.to_file_json(), private=True)
        emit({"did": key.did, "document": did_key_document(key.did), "key_file": str(args.out),
              "v1_kid": v1_kid_for_did_key(key.did), "registered_anywhere": False})
        return 0
    if action == "resolve":
        if args.did.startswith("did:key:"):
            document = did_key_document(args.did, encryption_key=args.encryption_key)
        else:
            document = Resolver(cache_dir=args.did_web_cache, allow_network=args.allow_network).resolve(args.did)
        emit({"did": args.did, "document": document})
        return 0
    if action == "from-key":
        did = did_key_from_pem(Path(args.public_key_file).read_text(encoding="utf-8"))
        emit({"did": did, "v1_kid": v1_kid_for_did_key(did)})
        return 0
    if action == "web-cache":
        did = Resolver(cache_dir=args.did_web_cache).add_web_document(_json(args.document))
        emit({"pinned": did, "cache": str(args.did_web_cache)})
        return 0
    if action == "delegate":
        key = DidKey.load(args.key)
        parents = _chain(args.parent)
        from .data_integrity import parse_time

        start, until = int(time.time()), int(time.time()) + args.ttl
        if parents:
            start = max(start, parse_time(parents[-1]["validFrom"]))
            until = min(until, parse_time(parents[-1]["validUntil"]))
        capability = dict(environments=args.environments, scopes=args.scopes, resources=args.resources,
                          tools=args.tools, per_action_minor=args.per_action, total_budget_minor=args.total,
                          approval_threshold_minor=args.threshold, max_delegation_depth=args.depth)
        signed = issue_delegation(key.signer, args.to, capability, valid_from=start, valid_until=until,
                                  parent=parents[-1] if parents else None)
        chain = [*parents, signed]
        if args.out:
            _write_json(args.out, chain)
        emit({"delegation": signed, "chain_length": len(chain), "chain_file": str(args.out) if args.out else None})
        return 0
    if action == "revoke":
        key = DidKey.load(args.key)
        chain = _chain(args.chain)
        index = len(chain) - 1 if args.index is None else args.index
        if not 0 <= index < len(chain):
            raise ValueError("--index is outside the chain")
        record = issue_revocation(key.signer, chain[index], revoked_at=int(time.time()), reason=args.reason)
        if args.out:
            _write_json(args.out, record)
        emit(record)
        return 0
    if action == "invoke":
        key = DidKey.load(args.key)
        invocation = issue_invocation(key.signer, _chain(args.chain), request_id=args.request_id or f"req:{uuid4()}",
                                      environment=args.environment, action=args.invoked_action, resource=args.resource,
                                      tool=args.tool, amount_minor=args.amount, created=int(time.time()), ttl=args.ttl)
        if args.out:
            _write_json(args.out, invocation)
        emit(invocation)
        return 0

    from . import service_did as sd

    service = service_factory()
    if action == "trust":
        emit(service.set_trusted_root(sd.TrustRootInput(environment=args.environment, did=args.root,
                                                        trusted=not args.remove)))
    elif action == "evaluate":
        result = service.evaluate_invocation(sd.InvocationEvaluateInput(invocation=_json(args.invocation)))
        if args.bundle_out:
            _write_json(args.bundle_out, result["bundle"])
        emit({k: v for k, v in result.items() if k != "bundle"} | {"bundle_file": str(args.bundle_out or "")})
    elif action == "record-revocation":
        emit(service.revoke_delegation(sd.RevocationInput(revocation=_json(args.file))))
    elif action == "revocations":
        listing = service.revocation_list(args.environment)
        if args.out:
            _write_json(args.out, listing)
        emit(listing)
    else:
        if args.ledger_action == "export":
            export = service.v2_ledger(args.environment)
            if args.out:
                _write_json(args.out, export)
            emit({"environment": args.environment, "issuer": export["issuer"], "head": export["head"],
                  "count": len(export["receipts"]), "file": str(args.out or "")})
        else:
            report = service.delegation_ledger(args.environment).verify(args.expected_head)
            emit(report)
            return 0 if report["valid"] else 1
    return 0
