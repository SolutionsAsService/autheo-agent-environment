"""v2 policy decision point and ledger for DID-based delegation chains.

One DelegationLedger per environment. It lives in the same SQLite file as the v1
ledger but in separate tables (v2_events, v2_revocations), so the v1 receipt chain
and its verifiers are untouched. The environment's authority key signs v2 receipts
as a did:key (the "environment DID").

evaluate(invocation):
  1. verify the invocation proof (invoker DID) and lifetime - failures are rejected;
  2. verify the embedded delegation chain back to its root DID against the trusted
     roots and every revocation record this environment has accepted - forged or
     broken chains are rejected; authentic-but-unauthorised chains (expired,
     revoked, widened, untrusted root) are recorded as BLOCK decisions;
  3. run the declarative policy with the leaf capability as the mandate, plus a
     cumulative budget check for every ancestor delegation;
  4. append an environment-signed, hash-linked receipt and return a self-contained
     bundle that verifier.py (or interop/js) can check offline.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from contextlib import closing

from .canonical import ZERO_HASH
from .data_integrity import ProofError, add_proof
from .delegation import (
    InvocationResult,
    document_digest,
    new_urn,
    pattern_matches,
    verify_invocation,
    verify_revocation,
)
from .did import DidKey, Resolver
from .environment import Environment
from .errors import ConflictError, NotFoundError
from .models import Request
from .policy import ChainBudget, ChainCheck, PolicyDocument, PriorEvent, evaluate
from .verifier import v2_chain_hash, verify_receipt, verify_receipts

V2_TABLES = """
CREATE TABLE IF NOT EXISTS v2_events (
    sequence INTEGER PRIMARY KEY, receipt_id TEXT UNIQUE NOT NULL, request_id TEXT UNIQUE,
    document TEXT NOT NULL, chain_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS v2_revocations (
    record_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, document TEXT NOT NULL);
"""
V2_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS v2_events_append_only_update BEFORE UPDATE ON v2_events
BEGIN SELECT RAISE(ABORT, 'autheo v2 ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS v2_events_append_only_delete BEFORE DELETE ON v2_events
BEGIN SELECT RAISE(ABORT, 'autheo v2 ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS v2_revocations_append_only_update BEFORE UPDATE ON v2_revocations
BEGIN SELECT RAISE(ABORT, 'autheo v2 revocations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS v2_revocations_append_only_delete BEFORE DELETE ON v2_revocations
BEGIN SELECT RAISE(ABORT, 'autheo v2 revocations are append-only'); END;
"""


class ChainRejected(ProofError):
    """The delegation chain is not authentic (forged, tampered, broken links)."""

    def __init__(self, errors: list[dict]):
        detail = "; ".join(f"link {e['index']}: {e['code']}" for e in errors[:5])
        super().__init__("chain_not_authentic", detail)
        self.errors = errors


def decide_invocation(result: InvocationResult, invocation: dict, *, environment_id: str, policy: PolicyDocument,
                      receipts: list[dict], at: int):
    """Pure v2 decision for a verified invocation; receipts = this environment's earlier v2 receipts.

    Raises ProofError for an invocation addressed elsewhere and ChainRejected for a chain that is not
    authentic. interop/js/autheo-did.mjs decideInvocation() mirrors this for the mandate-only policy
    (checked by tests/vectors/autheo-v2-venue-vectors.json).
    """
    chain, model = result.chain, result.invocation
    if model.environment != environment_id:
        raise ProofError("wrong_environment", f"invocation is addressed to {model.environment}")
    if not chain.authentic:
        raise ChainRejected([e.to_dict() for e in chain.errors])
    capability = chain.capability
    grouped: dict[tuple[int, str], list[str]] = {}
    for error in chain.errors:  # one reason per (link, code), as in the offline verifier
        grouped.setdefault((error.index, error.code), []).append(error.detail)
    checks = [ChainCheck(f"chain.{code}", True, f"delegation_{code}:{index}", "; ".join(details))
              for (index, code), details in grouped.items()]
    if not checks:
        checks.append(ChainCheck("chain.verified", False, "", f"{len(chain.links)} signed link(s) from root "
                                 f"{chain.root} to the invoker; none expired or revoked"))
    environment_ok = any(pattern_matches(p, environment_id) for p in capability.environments)
    checks.append(ChainCheck("chain.environment", not environment_ok, "environment_denied",
                             f"environment {environment_id} " + ("is delegated" if environment_ok else "is not delegated")))
    checks.append(ChainCheck("chain.asset", model.asset != capability.asset, "asset_mismatch",
                             f"amount is in {model.asset}, the grant is in {capability.asset}"))
    leaf_id = chain.links[-1]["id"]
    decisions = [r for r in receipts if r["kind"] == "decision"]
    history = [PriorEvent(decision=r["decision"], amount_minor=r.get("amount_minor", 0), action=r.get("action"),
                          tool=r.get("tool"), recorded_at=r["recorded_at"])
               for r in decisions if r.get("chain") and r["chain"][-1]["id"] == leaf_id]
    budgets = []
    for link, raw in zip(chain.links[:-1], invocation["capability"][:-1], strict=True):
        spent = sum(r.get("amount_minor", 0) for r in decisions if r["decision"] == "allow"
                    and any(item["id"] == link["id"] for item in r.get("chain", [])))
        limit = raw["credentialSubject"]["capability"]["total_budget_minor"]
        budgets.append(ChainBudget(str(link["index"]), limit, spent))
    request = Request(request_id=model.id, agent_id=model.invoker, environment=environment_id,
                      mandate_id=leaf_id, action=model.action, resource=model.resource, tool=model.tool,
                      amount_minor=model.amount_minor)
    return evaluate(policy=policy, mandate=capability, mandate_id=leaf_id, request=request,
                    revoked=False, history=history, now=at, chain_checks=checks, chain_budgets=budgets)


def _public(receipt: dict) -> dict:
    return {k: v for k, v in receipt.items() if k != "_hash"}


class DelegationLedger:
    def __init__(self, environment: Environment, *, trusted_roots: Iterable[str] = (),
                 resolver: Resolver | None = None, append_only: bool = False):
        self.environment = environment
        self.environment_id = environment.environment_id
        self.key = DidKey(environment.authority.key)
        self.did = self.key.did
        self.trusted_roots = set(trusted_roots)
        self.resolver = resolver or Resolver()
        with closing(environment.connect()) as db:
            db.executescript(V2_TABLES)
            if append_only:
                db.executescript(V2_TRIGGERS)

    # ------------------------------------------------------------------ reading
    def read(self, db) -> list[dict]:
        """All v2 receipts with their chain hash ("_hash"), verified; raises on any integrity failure."""
        previous, receipts = ZERO_HASH, []
        for sequence, document, stored_hash in db.execute(
            "SELECT sequence, document, chain_hash FROM v2_events ORDER BY sequence"
        ):
            receipt = json.loads(document)
            try:
                model = verify_receipt(receipt, self.resolver, self.did)
            except ProofError as error:
                raise ValueError("v2 ledger integrity failure") from error
            link = v2_chain_hash(previous, receipt)
            if (sequence != len(receipts) + 1 or model.sequence != sequence or model.previous_hash != previous
                    or link != stored_hash or model.environment != self.environment_id):
                raise ValueError("v2 ledger integrity failure")
            receipts.append({**receipt, "_hash": link})
            previous = link
        return receipts

    def revocations(self, db=None) -> list[dict]:
        if db is None:
            with closing(self.environment.connect()) as connection:
                return self.revocations(connection)
        return [json.loads(row[0]) for row in db.execute("SELECT document FROM v2_revocations ORDER BY rowid")]

    def receipts(self, limit: int | None = None) -> list[dict]:
        with closing(self.environment.connect()) as db:
            receipts = [_public(r) for r in self.read(db)]
        return receipts if limit is None else receipts[-limit:]

    def export(self) -> dict:
        with closing(self.environment.connect()) as db:
            receipts = self.read(db)
        return {"schema_version": "autheo.ledger-export/v2", "environment": self.environment_id, "issuer": self.did,
                "head": receipts[-1]["_hash"] if receipts else ZERO_HASH,
                "receipts": [_public(r) for r in receipts]}

    def verify(self, expected_head: str | None = None) -> dict:
        """Non-raising verification report of the v2 chain (same checks as the offline verifier)."""
        with closing(self.environment.connect()) as db:
            rows = db.execute("SELECT document, chain_hash FROM v2_events ORDER BY sequence").fetchall()
        report = verify_receipts([json.loads(row[0]) for row in rows], resolver=self.resolver, issuer=self.did,
                                 environment=self.environment_id, expected_head=expected_head)
        if report["valid"] and rows and rows[-1][1] != report["head"]:
            report["valid"] = False
            report["problems"].append({"sequence": len(rows), "problem": "stored_chain_hash_mismatch"})
        return report

    # ------------------------------------------------------------------ writing
    def _append(self, db, receipts: list[dict], body: dict) -> dict:
        now = int(time.time())
        document = {
            "type": "AutheoReceipt",
            "schema_version": "autheo.receipt/v2",
            "id": new_urn(),
            "issuer": self.did,
            "environment": self.environment_id,
            "sequence": len(receipts) + 1,
            "previous_hash": receipts[-1]["_hash"] if receipts else ZERO_HASH,
            "recorded_at": now,
            **{k: v for k, v in body.items() if v is not None},
            "executed": False,
            "simulation_only": True,
        }
        signed = add_proof(document, self.key.signer, "assertionMethod", now)
        verify_receipt(signed, self.resolver, self.did)
        link = v2_chain_hash(document["previous_hash"], signed)
        db.execute("INSERT INTO v2_events VALUES (?, ?, ?, ?, ?)",
                   (document["sequence"], document["id"], body.get("request_id"),
                    json.dumps(signed, separators=(",", ":")), link))
        return signed

    def record_revocation(self, record: dict) -> dict:
        """Accept a signed revocation record from anyone; it only takes effect where its signer is entitled."""
        model = verify_revocation(record, self.resolver)
        digest = document_digest(record)
        with self.environment.transaction() as db:
            existing = db.execute("SELECT document FROM v2_revocations WHERE record_id=?", (model.id,)).fetchone()
            receipts = self.read(db)
            if existing:
                if document_digest(json.loads(existing[0])) != digest:
                    raise ConflictError("A different revocation record with this id was already recorded")
                found = next(r for r in receipts if r.get("reference") == model.id and r["kind"] == "revocation")
                return {**_public(found), "replayed": True}
            db.execute("INSERT INTO v2_revocations VALUES (?, ?, ?)",
                       (model.id, model.target.id, json.dumps(record, separators=(",", ":"))))
            return self._append(db, receipts, {
                "kind": "revocation", "decision": "recorded", "document_digest": digest,
                "reasons": ["revocation_recorded", f"revocation_reason:{model.reason}"],
                "reference": model.id,
            })

    def evaluate(self, invocation: dict, *, now: int | None = None) -> dict:
        """Verify an invocation and its delegation chain, run policy, record and return a signed receipt + bundle."""
        if not isinstance(invocation, dict):
            raise ProofError("malformed", "invocation must be a JSON object")
        with self.environment.transaction() as db:
            at = int(time.time()) if now is None else now
            revocations = self.revocations(db)
            result = verify_invocation(invocation, resolver=self.resolver, at=at, trusted_roots=self.trusted_roots,
                                       revocations=revocations)
            chain = result.chain
            if not chain.authentic:
                raise ChainRejected([e.to_dict() for e in chain.errors])
            model = result.invocation
            if model.environment != self.environment_id:
                raise ValueError("Invocation is addressed to a different environment")
            receipts = self.read(db)
            existing = next((r for r in receipts if r.get("request_id") == model.id), None)
            if existing:
                if existing["document_digest"] != result.digest:
                    raise ConflictError("Idempotency key reused for a different invocation")
                receipt = _public(existing)
                return {"decision": None, "receipt": {**receipt, "replayed": True},
                        "bundle": self._bundle(receipt, invocation, revocations), "chain": chain.to_dict()}
            decision = decide_invocation(result, invocation, environment_id=self.environment_id,
                                         policy=self.environment.policy, receipts=receipts, at=at)
            receipt = self._append(db, receipts, {
                "kind": "decision", "decision": decision.decision, "reasons": decision.reasons,
                "document_digest": result.digest, "request_id": model.id, "invoker": model.invoker,
                "root": chain.root,
                "chain": [{k: link[k] for k in ("id", "digest", "issuer", "subject")} for link in chain.links],
                "action": model.action, "resource": model.resource, "tool": model.tool,
                "amount_minor": model.amount_minor, "asset": model.asset,
                "policy_id": self.environment.policy.policy_id,
                "policy_digest": self.environment.policy.digest,
            })
            return {"decision": decision, "receipt": receipt, "bundle": self._bundle(receipt, invocation, revocations),
                    "chain": chain.to_dict()}

    @staticmethod
    def _bundle(receipt: dict, invocation: dict, revocations: list[dict]) -> dict:
        link_ids = {link["id"] for link in receipt.get("chain", [])}
        relevant = [r for r in revocations if r.get("target", {}).get("id") in link_ids]
        return {"schema_version": "autheo.bundle/v2", "receipt": _public(receipt), "invocation": invocation,
                "revocations": relevant}

    def receipt(self, request_id: str) -> dict:
        found = next((r for r in self.receipts() if r.get("request_id") == request_id), None)
        if found is None:
            raise NotFoundError("No v2 decision receipt for this request")
        return found
