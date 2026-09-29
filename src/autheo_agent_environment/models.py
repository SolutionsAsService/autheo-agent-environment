from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,95}$", strict=True)]
Minor = Annotated[int, Field(strict=True, ge=0, le=10**15)]
Scope = Literal["marketplace.read", "devhub.read", "chain.read", "compute.simulate", "environment.handoff"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Passport(StrictModel):
    agent_id: Identifier
    owner_id: Identifier
    public_key: str = Field(max_length=256)
    environments: list[Identifier] = Field(min_length=1, max_length=20)


class Mandate(StrictModel):
    agent_id: Identifier
    owner_id: Identifier
    environment: Identifier
    scopes: list[Scope] = Field(min_length=1, max_length=5)
    resources: list[Identifier] = Field(min_length=1, max_length=50)
    destinations: list[Identifier] = Field(default_factory=list, max_length=20)
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
    request_id: Identifier
    agent_id: Identifier
    environment: Identifier
    mandate_id: str = Field(min_length=1, max_length=64)
    action: Scope
    resource: Identifier
    amount_minor: Minor = 0
    asset: Literal["DEMO"] = "DEMO"


class Checkpoint(StrictModel):
    task_id: Identifier
    step: Literal["planned", "inspected", "awaiting_review"]
    artifact_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]


class Handoff(StrictModel):
    agent_id: Identifier
    owner_id: Identifier
    source_environment: Identifier
    destination_environment: Identifier
    source_mandate_id: str = Field(min_length=1, max_length=64)
    passport_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    scopes: list[Scope] = Field(min_length=1, max_length=5)
    checkpoint: Checkpoint
    source_audit_head: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget_transferred_minor: Literal[0] = 0
    activation_requires_new_mandate: Literal[True] = True
