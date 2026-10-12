"""DID / delegation operations of the trust service (v2), shared by the CLI, HTTP API and web demo.

Nothing here is needed to VERIFY anything: verification is pure (verifier.py). The
service adds conveniences around the permissionless core - local-dev key custody
for demos, an environment ledger that records decisions and revocations, and a
revocation list export. Agent-held keys sign their own delegations/invocations and
only send signed documents.
"""

from __future__ import annotations

import time
from typing import Annotated
from uuid import uuid4

from pydantic import Field

from .data_integrity import parse_time
from .delegation import issue_delegation, issue_invocation, issue_revocation, verify_chain
from .did import DidKey, Resolver, did_key_document, v1_kid_for_did_key
from .didenv import DelegationLedger
from .errors import NotFoundError
from .models import Identifier, Minor, Scope, StrictModel, Timestamp, ToolName
from .models_v2 import (
    MAX_CHAIN_LENGTH,
    MAX_DELEGATION_SECONDS,
    MAX_INVOCATION_SECONDS,
    Capability,
    Delegation,
    Did,
)
from .verifier import verify_bundle

Document = dict
Reason = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")]


class DidCreateInput(StrictModel):
    custody: Annotated[str, Field(pattern=r"^local_dev_custody$")] = "local_dev_custody"


class TrustRootInput(StrictModel):
    environment: Identifier
    did: Did
    trusted: bool = True


class DelegateInput(StrictModel):
    """Sign a delegation with a key held by this local service (demo / local-dev custody only)."""

    issuer: Did
    subject: Did
    capability: Capability
    parent_chain: list[Document] = Field(default_factory=list, max_length=MAX_CHAIN_LENGTH - 1)
    ttl_seconds: Annotated[int, Field(strict=True, ge=10, le=MAX_DELEGATION_SECONDS)] = 3600
    valid_from: Timestamp | None = None


class RevocationInput(StrictModel):
    """Record a signed revocation, or sign one with a service-held key (issuer + chain [+ index])."""

    revocation: Document | None = None
    issuer: Did | None = None
    chain: list[Document] = Field(default_factory=list, max_length=MAX_CHAIN_LENGTH)
    index: Annotated[int, Field(strict=True, ge=0, lt=MAX_CHAIN_LENGTH)] | None = None
    reason: Reason = "revoked"


class InvokeInput(StrictModel):
    """Unsigned invocation fields; only usable when the invoker's key is held by this local service."""

    invoker: Did
    chain: list[Document] = Field(min_length=1, max_length=MAX_CHAIN_LENGTH)
    environment: Identifier
    action: Scope
    resource: Identifier
    tool: ToolName | None = None
    amount_minor: Minor = 0
    request_id: Identifier | None = None
    ttl_seconds: Annotated[int, Field(strict=True, ge=1, le=MAX_INVOCATION_SECONDS)] = 60


class InvocationEvaluateInput(StrictModel):
    invocation: Document | None = None
    request: InvokeInput | None = None


class ChainVerifyInput(StrictModel):
    chain: list[Document] = Field(min_length=1, max_length=MAX_CHAIN_LENGTH)
    trusted_roots: list[Did] = Field(default_factory=list, max_length=50)
    any_root: bool = False
    at: Timestamp | None = None
    revocations: list[Document] = Field(default_factory=list, max_length=1000)


class BundleVerifyInput(StrictModel):
    bundle: Document
    trusted_roots: list[Did] = Field(default_factory=list, max_length=50)
    any_root: bool = False
    environment_did: Did | None = None
    revocations: list[Document] = Field(default_factory=list, max_length=1000)


def _roots(trusted_roots: list[str], any_root: bool):
    if any_root:
        return None
    if not trusted_roots:
        raise ValueError("Name at least one trusted root DID, or set any_root=true explicitly")
    return trusted_roots


class DidServiceMixin:
    """Mixed into TrustService; expects self.state and self.environment()."""

    @property
    def resolver(self) -> Resolver:
        return Resolver(cache_dir=self.state.did_web_cache, allow_network=self.state.did_web_network)

    def delegation_ledger(self, environment_id: str) -> DelegationLedger:
        environment = self.environment(environment_id)
        ledgers = self.__dict__.setdefault("_delegation_ledgers", {})
        if environment_id not in ledgers:
            ledgers[environment_id] = DelegationLedger(environment, resolver=self.resolver, append_only=True)
        ledger = ledgers[environment_id]
        ledger.trusted_roots = set(self.state.trusted_roots(environment_id))
        return ledger

    def _held_key(self, did: str) -> DidKey:
        key = self.state.did_key(did)
        if key is None:
            raise ValueError(f"{did} is not held by this local service; sign the document with the agent's own key")
        return key

    # ------------------------------------------------------------------ DIDs
    def create_did(self, data: DidCreateInput) -> dict:
        key = DidKey.generate()
        self.state.store_did_key(key)
        return {"did": key.did, "document": did_key_document(key.did), "custody": data.custody,
                "v1_kid": v1_kid_for_did_key(key.did), "registered_anywhere": False}

    def list_dids(self) -> dict:
        return {"dids": self.state.list_dids(), "custody": "local_dev_custody"}

    def resolve_did(self, did: str) -> dict:
        document = self.resolver.resolve(did)
        method = did.split(":")[1]
        return {"did": did, "document": document, "method": method,
                "network_used": False if method == "key" else self.state.did_web_network}

    def set_trusted_root(self, data: TrustRootInput) -> dict:
        roots = self.state.set_trusted_root(data.environment, data.did, data.trusted)
        return {"environment": data.environment, "trusted_roots": roots}

    # ------------------------------------------------------------------ delegation
    def delegate(self, data: DelegateInput) -> dict:
        key = self._held_key(data.issuer)
        start = int(time.time()) if data.valid_from is None else data.valid_from
        parent = data.parent_chain[-1] if data.parent_chain else None
        until = start + data.ttl_seconds
        if parent is not None:
            parent_model = Delegation.model_validate(parent)
            until = min(until, parse_time(parent_model.validUntil))
            start = max(start, parse_time(parent_model.validFrom))
        signed = issue_delegation(key.signer, data.subject, data.capability, valid_from=start, valid_until=until,
                                  parent=parent)
        chain = [*data.parent_chain, signed]
        return {"delegation": signed, "chain": chain, "custody": "local_dev_custody"}

    def revoke_delegation(self, data: RevocationInput) -> dict:
        if data.revocation is None:
            if data.issuer is None or not data.chain:
                raise ValueError("Provide a signed revocation, or issuer plus the chain to revoke from")
            index = len(data.chain) - 1 if data.index is None else data.index
            if index >= len(data.chain):
                raise ValueError("index is outside the chain")
            record = issue_revocation(self._held_key(data.issuer).signer, data.chain[index],
                                      revoked_at=int(time.time()), reason=data.reason)
        else:
            record = data.revocation
        receipts = {}
        for environment_id in self.state.environments:
            receipts[environment_id] = self.delegation_ledger(environment_id).record_revocation(record)
        return {"revocation": record, "receipts": receipts}

    def revocation_list(self, environment_id: str) -> dict:
        ledger = self.delegation_ledger(environment_id)
        return {"schema_version": "autheo.revocation-list/v2", "source": environment_id,
                "generated_at": int(time.time()), "records": ledger.revocations()}

    def evaluate_invocation(self, data: InvocationEvaluateInput) -> dict:
        if (data.invocation is None) == (data.request is None):
            raise ValueError("Provide exactly one of invocation or request")
        proof = "invoker_signed"
        invocation = data.invocation
        if invocation is None:
            request = data.request
            invocation = issue_invocation(
                self._held_key(request.invoker).signer, request.chain, request_id=request.request_id or f"req:{uuid4()}",
                environment=request.environment, action=request.action, resource=request.resource, tool=request.tool,
                amount_minor=request.amount_minor, created=int(time.time()), ttl=request.ttl_seconds)
            proof = "service_held_key_local_dev"
        environment_id = invocation.get("environment") if isinstance(invocation, dict) else None
        if not isinstance(environment_id, str) or environment_id not in self.state.environments:
            raise NotFoundError(f"Environment {environment_id!r} is not configured")
        result = self.delegation_ledger(environment_id).evaluate(invocation)
        decision, receipt = result["decision"], result["receipt"]
        return {
            "decision": decision.model_dump(mode="json") if decision else None,
            "outcome": receipt["decision"],
            "reasons": receipt["reasons"],
            "replayed": bool(receipt.get("replayed")),
            "request_proof": proof,
            "executed": False,
            "receipt": receipt,
            "bundle": result["bundle"],
            "chain": result["chain"],
        }

    # ------------------------------------------------------------------ verification (pure)
    def verify_delegation_chain(self, data: ChainVerifyInput) -> dict:
        at = int(time.time()) if data.at is None else data.at
        result = verify_chain(data.chain, resolver=self.resolver, at=at,
                              trusted_roots=_roots(data.trusted_roots, data.any_root), revocations=data.revocations)
        return {**result.to_dict(), "root_pinned": not data.any_root}

    def verify_bundle(self, data: BundleVerifyInput) -> dict:
        return verify_bundle(data.bundle, resolver=self.resolver, trusted_roots=_roots(data.trusted_roots, data.any_root),
                             environment_did=data.environment_did, extra_revocations=data.revocations)

    def v2_ledger(self, environment_id: str) -> dict:
        return self.delegation_ledger(environment_id).export()
