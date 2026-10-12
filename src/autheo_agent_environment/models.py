"""Strict, versioned document models. JSON Schemas in schemas/ are generated from these."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,95}$", strict=True)]
ToolName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$", strict=True)]
ReasonCode = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*(:[A-Za-z0-9:._-]{1,96})?$", strict=True)]
Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
Minor = Annotated[int, Field(strict=True, ge=0, le=10**15)]
Timestamp = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
DocumentId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$", strict=True)]

# Enumerated action vocabulary. The first five are the original 0.1 scopes; the rest
# were added in schema v1 for agent-runtime integrations (JARVIS, Paperclip). A
# mandate only ever grants exact members of this list; wildcards are never granted.
Scope = Literal[
    "marketplace.read",
    "devhub.read",
    "chain.read",
    "compute.simulate",
    "environment.handoff",
    "tool.invoke",
    "model.invoke",
    "file.read",
    "file.write",
    "network.fetch",
    "message.send",
    "task.checkpoint",
]
SCOPES: tuple[str, ...] = Scope.__args__  # type: ignore[attr-defined]

Outcome = Literal["allow", "escalate", "block"]
ReceiptKind = Literal[
    "simulation",
    "handoff_export",
    "handoff_import",
    "revocation",
    "outcome_report",
    "identity_issue",
    "mandate_grant",
]
RECEIPT_KINDS: tuple[str, ...] = ReceiptKind.__args__  # type: ignore[attr-defined]
ReceiptDecision = Literal["allow", "escalate", "block", "checkpoint_only", "revoked", "recorded"]
ReportedStatus = Literal["succeeded", "failed", "unknown"]

SCHEMA_VERSIONS = {
    "passport": "autheo.passport/v1",
    "mandate": "autheo.mandate/v1",
    "request": "autheo.request/v1",
    "decision": "autheo.decision/v1",
    "receipt": "autheo.receipt/v1",
    "checkpoint": "autheo.checkpoint/v1",
    "handoff": "autheo.handoff/v1",
    "outcome": "autheo.outcome/v1",
    "policy": "autheo.policy/v1",
}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Passport(StrictModel):
    """Issuer assertion binding an agent identifier and owner to an Ed25519 public key."""

    schema_version: Literal["autheo.passport/v1"] = "autheo.passport/v1"
    agent_id: Identifier
    owner_id: Identifier
    public_key: str = Field(max_length=256)
    environments: list[Identifier] = Field(min_length=1, max_length=20)


class Mandate(StrictModel):
    """Scoped, budgeted, short-lived delegation from an owner to an agent."""

    schema_version: Literal["autheo.mandate/v1"] = "autheo.mandate/v1"
    agent_id: Identifier
    owner_id: Identifier
    environment: Identifier
    scopes: list[Scope] = Field(min_length=1, max_length=len(SCOPES))
    resources: list[Identifier] = Field(min_length=1, max_length=50)
    destinations: list[Identifier] = Field(default_factory=list, max_length=20)
    tools: list[ToolName] = Field(default_factory=list, max_length=100)
    asset: Literal["DEMO"] = "DEMO"
    per_action_minor: Minor
    total_budget_minor: Minor
    approval_threshold_minor: Minor

    @model_validator(mode="after")
    def limits(self):
        if not self.approval_threshold_minor <= self.per_action_minor <= self.total_budget_minor:
            raise ValueError("approval threshold <= per-action limit <= total budget is required")
        return self


class Request(StrictModel):
    """Agent-signed proposal of one exact action. It is never an execution result."""

    schema_version: Literal["autheo.request/v1"] = "autheo.request/v1"
    request_id: Identifier
    agent_id: Identifier
    environment: Identifier
    mandate_id: str = Field(min_length=1, max_length=64)
    action: Scope
    resource: Identifier
    tool: ToolName | None = None
    amount_minor: Minor = 0
    asset: Literal["DEMO"] = "DEMO"


class Checkpoint(StrictModel):
    task_id: Identifier
    step: Literal["planned", "inspected", "awaiting_review"]
    artifact_sha256: Hex64


class Handoff(StrictModel):
    schema_version: Literal["autheo.handoff/v1"] = "autheo.handoff/v1"
    agent_id: Identifier
    owner_id: Identifier
    source_environment: Identifier
    destination_environment: Identifier
    source_mandate_id: str = Field(min_length=1, max_length=64)
    passport_digest: Hex64
    scopes: list[Scope] = Field(min_length=1, max_length=len(SCOPES))
    checkpoint: Checkpoint
    source_audit_head: Hex64
    budget_transferred_minor: Literal[0] = 0
    activation_requires_new_mandate: Literal[True] = True


class OutcomeReport(StrictModel):
    """Executor-reported outcome of a previously allowed request (optionally agent-signed).

    Recording it proves only that the report was received, not that the action happened.
    """

    schema_version: Literal["autheo.outcome/v1"] = "autheo.outcome/v1"
    request_id: Identifier
    agent_id: Identifier
    environment: Identifier
    status: ReportedStatus
    detail_sha256: Hex64 | None = None


class Explanation(StrictModel):
    check: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.:-]{0,95}$", strict=True)]
    outcome: Literal["pass", "fail", "escalate", "not_applicable"]
    detail: str = Field(max_length=300)


class BudgetState(StrictModel):
    asset: Literal["DEMO"] = "DEMO"
    total_budget_minor: Minor
    spent_minor: Minor
    remaining_minor: Minor


class Decision(StrictModel):
    """Policy-decision-point result. Not a capability token and not an execution result."""

    schema_version: Literal["autheo.decision/v1"] = "autheo.decision/v1"
    request_id: Identifier
    agent_id: Identifier
    environment: Identifier
    mandate_id: str = Field(min_length=1, max_length=64)
    action: Scope
    resource: Identifier
    tool: ToolName | None = None
    amount_minor: Minor
    decision: Outcome
    reasons: list[ReasonCode] = Field(min_length=1, max_length=64)
    explanation: list[Explanation] = Field(max_length=128)
    policy_id: Identifier
    policy_digest: Hex64
    request_digest: Hex64
    budget: BudgetState
    evaluated_at: Timestamp
    executed: Literal[False] = False
    is_capability: Literal[False] = False


class ReceiptBody(StrictModel):
    """Body of a signed autheo-receipt+jwt. Hash-linked to its predecessor."""

    schema_version: Literal["autheo.receipt/v1"] = "autheo.receipt/v1"
    sequence: Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
    previous_hash: Hex64
    request_id: DocumentId
    payload_hash: Hex64
    agent_id: Identifier
    mandate_id: str = Field(min_length=1, max_length=64)
    kind: ReceiptKind
    decision: ReceiptDecision
    reasons: list[ReasonCode] = Field(max_length=64)
    amount_minor: Minor
    executed: Literal[False] = False
    simulation_only: Literal[True] = True
    recorded_at: Timestamp
    action: Scope | None = None
    resource: Identifier | None = None
    tool: ToolName | None = None
    policy_id: Identifier | None = None
    policy_digest: Hex64 | None = None
    checkpoint: Checkpoint | None = None
    reference: DocumentId | None = None
    reported_status: ReportedStatus | None = None
    reported_by: Literal["operator_api", "agent_signed"] | None = None


class LedgerEntry(StrictModel):
    """One stored row of the append-only ledger (SQLite events table / archive)."""

    sequence: Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
    request_id: DocumentId
    token: str = Field(min_length=1, max_length=131072)
    chain_hash: Hex64
