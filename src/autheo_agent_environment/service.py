"""Transport-neutral trust service used by the CLI, the HTTP API and the web demo.

Operations: issue identity (passport), grant/revoke mandate, evaluate action,
record outcome receipt, verify receipt/ledger, checkpoint/handoff. Every input
is a strict Pydantic model so the same contract backs the OpenAPI document.
"""

from __future__ import annotations

import threading
import time
from typing import Annotated
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field

from .canonical import digest
from .environment import Environment
from .errors import ConflictError, NotFoundError
from .models import (
    Checkpoint,
    Hex64,
    Identifier,
    Mandate,
    Minor,
    Passport,
    ReportedStatus,
    Request,
    Scope,
    StrictModel,
    ToolName,
)
from .signing import MAX_TTL, key_fingerprint, public_pem, read_public, unverified_claims, verify
from .state import StateDir

Token = Annotated[str, Field(min_length=16, max_length=131072)]


# ---------------------------------------------------------------------- API inputs
class IdentityIssueInput(StrictModel):
    agent_id: Identifier
    owner_id: Identifier
    environments: list[Identifier] = Field(min_length=1, max_length=20)
    public_key: str | None = Field(default=None, max_length=4096)
    generate_key: bool = False
    ttl_seconds: Annotated[int, Field(strict=True, ge=60, le=MAX_TTL["passport"])] = MAX_TTL["passport"]


class MandateGrantInput(StrictModel):
    agent_id: Identifier
    environment: Identifier
    scopes: list[Scope] = Field(min_length=1)
    resources: list[Identifier] = Field(min_length=1, max_length=50)
    tools: list[ToolName] = Field(default_factory=list, max_length=100)
    destinations: list[Identifier] = Field(default_factory=list, max_length=20)
    per_action_minor: Minor
    total_budget_minor: Minor
    approval_threshold_minor: Minor
    ttl_seconds: Annotated[int, Field(strict=True, ge=10, le=MAX_TTL["mandate"])] = MAX_TTL["mandate"]


class RevokeInput(StrictModel):
    reason: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")] = "operator_revoked"


class ActionInput(StrictModel):
    """Unsigned request fields; only usable for agents whose key is held by this local service."""

    agent_id: Identifier
    mandate_id: str = Field(min_length=1, max_length=64)
    action: Scope
    resource: Identifier
    tool: ToolName | None = None
    amount_minor: Minor = 0
    request_id: Identifier | None = None


class EvaluateInput(StrictModel):
    request_token: Token | None = None
    request: ActionInput | None = None


class OutcomeInput(StrictModel):
    environment: Identifier
    request_id: Identifier
    status: ReportedStatus
    detail_sha256: Hex64 | None = None
    report_token: Token | None = None


class VerifyReceiptInput(StrictModel):
    token: Token


class CheckpointInput(StrictModel):
    agent_id: Identifier
    mandate_id: str = Field(min_length=1, max_length=64)
    destination: Identifier
    scopes: list[Scope] = Field(min_length=1)
    checkpoint: Checkpoint


class HandoffAcceptInput(StrictModel):
    handoff_token: Token
    allowed_scopes: list[Scope] = Field(min_length=1)


class LedgerVerifyInput(StrictModel):
    environment: Identifier
    expected_head: Hex64 | None = None


# ---------------------------------------------------------------------- service
class TrustService:
    def __init__(self, state: StateDir):
        self.state = state
        self.authority = state.authority
        self.policy = state.policy()
        self._environments: dict[str, Environment] = {}
        self._lock = threading.Lock()

    @classmethod
    def ephemeral(cls, environments: list[str] | None = None, policy_text: str | None = None):
        return cls(StateDir.ephemeral(environments, policy_text))

    def close(self) -> None:
        self.state.close()

    # ------------------------------------------------------------------ helpers
    def environment(self, environment_id: str) -> Environment:
        if environment_id not in self.state.environments:
            raise NotFoundError(f"Environment {environment_id!r} is not configured")
        with self._lock:
            if environment_id not in self._environments:
                self._environments[environment_id] = Environment(
                    self.state.ledger_path(environment_id),
                    environment_id,
                    self.authority,
                    self.policy,
                    append_only=True,
                )
            return self._environments[environment_id]

    def _identity(self, agent_id: str) -> dict:
        identity = self.state.get_identity(agent_id)
        if identity is None:
            raise NotFoundError(f"No identity for {agent_id!r}")
        return identity

    def _mandate(self, mandate_id: str) -> dict:
        mandate = self.state.get_mandate(mandate_id)
        if mandate is None:
            raise NotFoundError(f"No mandate {mandate_id!r}")
        return mandate

    def _receipt_response(self, environment: Environment, receipt: dict) -> dict:
        stored = environment.receipt(receipt["request_id"])
        return {"receipt": receipt, "receipt_token": stored["token"] if stored else None}

    # ------------------------------------------------------------------ identity
    def issue_identity(self, data: IdentityIssueInput) -> dict:
        for environment_id in data.environments:
            self.environment(environment_id)
        if (data.public_key is None) == (not data.generate_key):
            raise ValueError("Provide exactly one of public_key or generate_key=true")
        existing = self.state.get_identity(data.agent_id)
        if existing and any(
            self.environment(e).revoked(existing["passport_id"])
            for e in self.state.environments
            if self.state.ledger_path(e).exists()
        ):
            raise ConflictError("This agent identity was revoked; enroll a new agent id")
        if data.generate_key:
            if existing and existing["custody"] != "local_dev_custody":
                raise ConflictError("Agent already has an agent-held key; supply that public key")
            signer = self.state.agent_signer(data.agent_id)
            key = signer.key if signer else Ed25519PrivateKey.generate()
            if signer is None:
                self.state.store_agent_key(data.agent_id, key)
            public_key, custody = public_pem(key.public_key()), "local_dev_custody"
        else:
            read_public(data.public_key)
            public_key, custody = data.public_key, "agent_held"
        if existing and (existing["public_key"].strip() != public_key.strip() or existing["owner_id"] != data.owner_id):
            raise ConflictError("Agent identity exists with a different key or owner; key rotation is not supported")
        passport = Passport(
            agent_id=data.agent_id, owner_id=data.owner_id, public_key=public_key, environments=data.environments
        )
        token = self.authority.issue(
            "passport", data.agent_id, "autheo-agent-environment", passport.model_dump(), ttl=data.ttl_seconds
        )
        claims = verify(token, "passport", self.authority.public_key, self.authority.issuer,
                        "autheo-agent-environment", self.authority.kid)
        self.state.put_identity(
            dict(agent_id=data.agent_id, owner_id=data.owner_id, passport_id=claims["jti"], passport_token=token,
                 public_key=public_key, custody=custody, expires_at=claims["exp"], issued_at=claims["iat"])
        )
        receipts = []
        for environment_id in data.environments:
            environment = self.environment(environment_id)
            receipt = environment.record_event(
                request_id="identity:" + claims["jti"], payload_hash=digest(token), agent_id=data.agent_id,
                mandate_id=claims["jti"], kind="identity_issue",
                reasons=["issuer_asserted_identity", "not_a_did"], reference=claims["jti"],
            )
            receipts.append(self._receipt_response(environment, receipt))
        return {
            "agent_id": data.agent_id,
            "passport_id": claims["jti"],
            "passport_token": token,
            "passport": passport.model_dump(),
            "expires_at": claims["exp"],
            "custody": custody,
            "key_fingerprint": key_fingerprint(read_public(public_key)),
            "identifier_type": "local identifiers asserted by a configured issuer; not DIDs",
            "receipts": receipts,
        }

    def get_identity(self, agent_id: str) -> dict:
        identity = self._identity(agent_id)
        revoked = any(
            self.environment(e).revoked(identity["passport_id"])
            for e in self.state.environments
            if self.state.ledger_path(e).exists()
        )
        return {
            "agent_id": identity["agent_id"],
            "owner_id": identity["owner_id"],
            "passport_id": identity["passport_id"],
            "passport_token": identity["passport_token"],
            "custody": identity["custody"],
            "key_fingerprint": key_fingerprint(read_public(identity["public_key"])),
            "expires_at": identity["expires_at"],
            "expired": identity["expires_at"] <= int(time.time()),
            "revoked": revoked,
            "mandates": [m["mandate_id"] for m in self.state.list_mandates(agent_id)],
        }

    def revoke_identity(self, agent_id: str, data: RevokeInput) -> dict:
        identity = self._identity(agent_id)
        passport = Passport.model_validate(unverified_claims(identity["passport_token"])["body"])
        receipts = []
        for environment_id in passport.environments:
            environment = self.environment(environment_id)
            receipt = environment.revoke(identity["passport_id"], agent_id=agent_id, reason=data.reason)
            receipts.append(self._receipt_response(environment, receipt))
        return {"agent_id": agent_id, "passport_id": identity["passport_id"], "revoked": True, "receipts": receipts}

    # ------------------------------------------------------------------ mandates
    def grant_mandate(self, data: MandateGrantInput) -> dict:
        identity = self._identity(data.agent_id)
        environment = self.environment(data.environment)
        passport = Passport.model_validate(unverified_claims(identity["passport_token"])["body"])
        if data.environment not in passport.environments:
            raise ValueError("The agent's passport does not include this environment")
        if environment.revoked(identity["passport_id"]):
            raise ValueError("The agent's passport is revoked")
        mandate = Mandate(
            agent_id=data.agent_id, owner_id=identity["owner_id"], environment=data.environment,
            scopes=data.scopes, resources=data.resources, destinations=data.destinations, tools=data.tools,
            per_action_minor=data.per_action_minor, total_budget_minor=data.total_budget_minor,
            approval_threshold_minor=data.approval_threshold_minor,
        )
        token = self.authority.issue("mandate", data.agent_id, data.environment, mandate.model_dump(),
                                     ttl=data.ttl_seconds)
        claims = environment.owner_document(token, "mandate", data.environment)
        self.state.put_mandate(dict(mandate_id=claims["jti"], agent_id=data.agent_id, environment=data.environment,
                                    mandate_token=token, expires_at=claims["exp"], granted_at=claims["iat"]))
        receipt = environment.record_event(
            request_id="grant:" + claims["jti"], payload_hash=digest(token), agent_id=data.agent_id,
            mandate_id=claims["jti"], kind="mandate_grant", reasons=["operator_granted"], reference=claims["jti"],
        )
        return {
            "mandate_id": claims["jti"],
            "mandate_token": token,
            "mandate": mandate.model_dump(),
            "expires_at": claims["exp"],
            **self._receipt_response(environment, receipt),
        }

    def mandate_status(self, mandate_id: str) -> dict:
        row = self._mandate(mandate_id)
        environment = self.environment(row["environment"])
        identity = self._identity(row["agent_id"])
        mandate = Mandate.model_validate(unverified_claims(row["mandate_token"])["body"])
        spent = environment.spent(mandate_id)
        return {
            "mandate_id": mandate_id,
            "agent_id": row["agent_id"],
            "environment": row["environment"],
            "mandate": mandate.model_dump(),
            "expires_at": row["expires_at"],
            "expired": row["expires_at"] <= int(time.time()),
            "revoked": environment.revoked(mandate_id, identity["passport_id"]),
            "spent_minor": spent,
            "remaining_minor": max(0, mandate.total_budget_minor - spent),
            "asset": "DEMO",
        }

    def revoke_mandate(self, mandate_id: str, data: RevokeInput) -> dict:
        row = self._mandate(mandate_id)
        environment = self.environment(row["environment"])
        receipt = environment.revoke(mandate_id, agent_id=row["agent_id"], reason=data.reason)
        return {"mandate_id": mandate_id, "revoked": True, **self._receipt_response(environment, receipt)}

    # ------------------------------------------------------------------ decisions
    def evaluate(self, data: EvaluateInput) -> dict:
        if (data.request_token is None) == (data.request is None):
            raise ValueError("Provide exactly one of request_token or request")
        proof = "agent_signed_request"
        if data.request_token is not None:
            claims = unverified_claims(data.request_token)  # routing only; verified below
            body = claims.get("body") if isinstance(claims.get("body"), dict) else {}
            agent_id, mandate_id, token = claims.get("sub"), body.get("mandate_id"), data.request_token
            if not isinstance(agent_id, str) or not isinstance(mandate_id, str):
                raise ValueError("Request token lacks subject or mandate id")
        else:
            agent_id, mandate_id = data.request.agent_id, data.request.mandate_id
            signer = self.state.agent_signer(agent_id)
            if signer is None:
                raise ValueError("Unsigned requests are only accepted for agents with a service-held key")
            row = self._mandate(mandate_id)
            request = Request(
                request_id=data.request.request_id or f"req:{uuid4()}",
                agent_id=agent_id,
                environment=row["environment"],
                mandate_id=mandate_id,
                action=data.request.action,
                resource=data.request.resource,
                tool=data.request.tool,
                amount_minor=data.request.amount_minor,
            )
            token = signer.issue("request", agent_id, row["environment"], request.model_dump())
            proof = "service_held_key_local_dev"
        row = self._mandate(mandate_id)
        if row["agent_id"] != agent_id:
            raise ValueError("Request identity, mandate, or environment mismatch")
        identity = self._identity(agent_id)
        environment = self.environment(row["environment"])
        result = environment.evaluate(identity["passport_token"], row["mandate_token"], token)
        receipt = result["receipt"]
        decision = result["decision"]
        return {
            "decision": decision.model_dump(mode="json") if decision else None,
            "outcome": receipt["decision"],
            "reasons": receipt["reasons"],
            "replayed": bool(receipt.get("replayed")),
            "request_proof": proof,
            "executed": False,
            **self._receipt_response(environment, receipt),
        }

    def record_outcome(self, data: OutcomeInput) -> dict:
        environment = self.environment(data.environment)
        found = environment.receipt(data.request_id)
        if found is None:
            raise NotFoundError("No decision receipt exists for this request")
        identity = self._identity(found["receipt"]["agent_id"])
        receipt = environment.record_outcome(
            data.request_id, data.status, detail_sha256=data.detail_sha256, report_token=data.report_token,
            agent_public_key=identity["public_key"],
        )
        return self._receipt_response(environment, receipt)

    # ------------------------------------------------------------------ verification
    def verify_receipt(self, data: VerifyReceiptInput) -> dict:
        audience = unverified_claims(data.token).get("aud")
        if not isinstance(audience, str):
            raise ValueError("Receipt has no environment audience")
        return self.environment(audience).verify_receipt(data.token)

    def verify_ledger(self, data: LedgerVerifyInput) -> dict:
        environment = self.environment(data.environment)
        if not environment.path.exists():
            raise NotFoundError("Ledger does not exist yet")
        return environment.verify_ledger(data.expected_head)

    def receipts(self, environment_id: str, limit: int = 50, agent_id: str | None = None) -> dict:
        environment = self.environment(environment_id)
        audit = environment.audit()
        return {**audit, "environment": environment_id,
                "receipts": environment.receipts(limit=limit, agent_id=agent_id)}

    # ------------------------------------------------------------------ checkpoints
    def checkpoint(self, data: CheckpointInput) -> dict:
        row = self._mandate(data.mandate_id)
        if row["agent_id"] != data.agent_id:
            raise ValueError("Mandate does not belong to this agent")
        identity = self._identity(data.agent_id)
        self.environment(data.destination)
        source = self.environment(row["environment"])
        token = source.prepare_handoff(identity["passport_token"], row["mandate_token"], data.destination,
                                       data.scopes, data.checkpoint)
        jti = source.owner_document(token, "handoff", data.destination)["jti"]
        receipt = source.receipt("export:" + jti)
        return {"handoff_token": token, "handoff_id": jti, "source_environment": row["environment"],
                "destination_environment": data.destination, "budget_transferred_minor": 0,
                "receipt": receipt["receipt"], "receipt_token": receipt["token"]}

    def accept_handoff(self, data: HandoffAcceptInput) -> dict:
        claims = unverified_claims(data.handoff_token)  # routing only; fully verified by accept_handoff
        destination = self.environment(claims.get("aud") if isinstance(claims.get("aud"), str) else "")
        body = claims.get("body") if isinstance(claims.get("body"), dict) else {}
        row = self._mandate(str(body.get("source_mandate_id", "")))
        identity = self._identity(row["agent_id"])
        receipt = destination.accept_handoff(data.handoff_token, identity["passport_token"],
                                             row["mandate_token"], data.allowed_scopes)
        return {**self._receipt_response(destination, receipt), "activation_requires_new_mandate": True}

    # ------------------------------------------------------------------ info
    def info(self) -> dict:
        return {
            "service": "autheo-agent-environment",
            "mode": "local_reference",
            "issuer": self.authority.issuer,
            "kid": self.authority.kid,
            "public_key": public_pem(self.authority.public_key),
            "environments": self.state.environments,
            "policy_id": self.policy.policy_id,
            "policy_digest": self.policy.digest,
            "custody": "local_development_file_key",
            "executes_actions": False,
            "production_did_wallet_or_payments": False,
        }

    def policy_document(self) -> dict:
        return {"policy": self.policy.model_dump(mode="json"), "policy_digest": self.policy.digest}


__all__ = [
    "ActionInput", "CheckpointInput", "EvaluateInput", "HandoffAcceptInput", "IdentityIssueInput",
    "LedgerVerifyInput", "MandateGrantInput", "OutcomeInput", "RevokeInput", "TrustService",
    "VerifyReceiptInput",
]
