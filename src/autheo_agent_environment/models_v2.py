"""Strict v2 document models (DIDs, delegations, invocations, revocations, receipts, bundles).

JSON Schemas schemas/*.v2.schema.json are generated from these models. Models are
used for STRUCTURAL validation only: signatures are always verified over the exact
received JSON object (see data_integrity.py), never over a re-serialised model.
Normative text: docs/SPEC-DID.md.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import ConfigDict, Field, StringConstraints, field_validator, model_validator

from .models import Hex64, Identifier, Minor, ReasonCode, Scope, StrictModel, Timestamp, ToolName

VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
MAX_CHAIN_LENGTH = 10
MAX_DELEGATION_DEPTH = 8
MAX_DELEGATION_SECONDS = 30 * 86400
MAX_INVOCATION_SECONDS = 300

# DIDs usable in the Autheo v2 profile: did:key (Ed25519) and did:web without a port,
# at most 96 characters so a DID is also a valid v1 identifier (decisions reuse v1 models).
Did = Annotated[str, StringConstraints(pattern=r"^did:(key|web):[A-Za-z0-9._:-]{1,88}$", strict=True)]
DidUrl = Annotated[str, StringConstraints(pattern=r"^did:(key|web):[A-Za-z0-9._:-]{1,88}#[A-Za-z0-9._~:-]{1,128}$",
                                          strict=True)]
Urn = Annotated[str, StringConstraints(
    pattern=r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", strict=True)]
DateTime = Annotated[str, StringConstraints(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
                                            strict=True)]
# Grant patterns: an exact value, "prefix*" (every value starting with prefix) or "*" (everything).
GrantPattern = Annotated[str, StringConstraints(pattern=r"^(\*|[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}\*?)$", strict=True)]
# Denomination of every *_minor amount: "DEMO" (default) or a venue asset id such as "erc20:0x...".
AssetId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,63}$", strict=True)]
ProofValue = Annotated[str, StringConstraints(pattern=r"^z[1-9A-HJ-NP-Za-km-z]{80,96}$", strict=True)]
ProofPurpose = Literal["assertionMethod", "authentication", "capabilityDelegation", "capabilityInvocation"]


class AliasModel(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True)


class DataIntegrityProof(AliasModel):
    """Autheo profile of a W3C Data Integrity proof (eddsa-jcs-2022, single proof)."""

    type: Literal["DataIntegrityProof"]
    cryptosuite: Literal["eddsa-jcs-2022"]
    created: DateTime
    verificationMethod: DidUrl
    proofPurpose: ProofPurpose
    context: list[str] | None = Field(default=None, alias="@context", max_length=8)
    proofValue: ProofValue


def _unique(values: list) -> list:
    if len(values) != len(set(values)):
        raise ValueError("list items must be unique")
    return values


class Capability(StrictModel):
    """What a delegation grants. A child delegation may only narrow every field of its parent."""

    schema_version: Literal["autheo.capability/v2"] = "autheo.capability/v2"
    environments: list[GrantPattern] = Field(min_length=1, max_length=20)
    scopes: list[Scope] = Field(min_length=1, max_length=12)
    resources: list[GrantPattern] = Field(min_length=1, max_length=50)
    tools: list[GrantPattern] = Field(default_factory=list, max_length=100)
    asset: AssetId = "DEMO"
    per_action_minor: Minor
    total_budget_minor: Minor
    approval_threshold_minor: Minor
    max_delegation_depth: Annotated[int, Field(strict=True, ge=0, le=MAX_DELEGATION_DEPTH)] = 0

    @field_validator("environments", "scopes", "resources", "tools")
    @classmethod
    def unique_items(cls, values: list) -> list:
        return _unique(values)

    @model_validator(mode="after")
    def limits(self):
        if not self.approval_threshold_minor <= self.per_action_minor <= self.total_budget_minor:
            raise ValueError("approval threshold <= per-action limit <= total budget is required")
        return self


class ParentRef(StrictModel):
    id: Urn
    digest: Hex64


class DelegationSubject(StrictModel):
    id: Did
    schema_version: Literal["autheo.delegation/v2"] = "autheo.delegation/v2"
    capability: Capability
    parent: ParentRef | None = None


class Delegation(AliasModel):
    """A W3C VC 2.0 credential by which issuer (a DID) delegates a capability to credentialSubject.id."""

    context: list[Literal["https://www.w3.org/ns/credentials/v2"]] = Field(alias="@context", min_length=1,
                                                                            max_length=1)
    type: list[Literal["VerifiableCredential", "AutheoDelegation"]] = Field(min_length=2, max_length=2)
    id: Urn
    issuer: Did
    validFrom: DateTime
    validUntil: DateTime
    credentialSubject: DelegationSubject
    proof: DataIntegrityProof

    @model_validator(mode="after")
    def vc_type(self):
        if self.type != ["VerifiableCredential", "AutheoDelegation"]:
            raise ValueError('type must be ["VerifiableCredential", "AutheoDelegation"]')
        if self.proof.proofPurpose != "capabilityDelegation":
            raise ValueError("delegations are signed with proofPurpose capabilityDelegation")
        return self


class RevocationTarget(StrictModel):
    id: Urn
    digest: Hex64


class Revocation(AliasModel):
    """Signed statement that a delegation (and everything below it) is revoked from revoked_at on."""

    type: Literal["AutheoRevocation"]
    schema_version: Literal["autheo.revocation/v2"] = "autheo.revocation/v2"
    id: Urn
    issuer: Did
    target: RevocationTarget
    revoked_at: DateTime
    reason: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$", strict=True)] = "revoked"
    proof: DataIntegrityProof

    @model_validator(mode="after")
    def purpose(self):
        if self.proof.proofPurpose != "assertionMethod":
            raise ValueError("revocations are signed with proofPurpose assertionMethod")
        return self


class RevocationList(StrictModel):
    """Unsigned container: every record is independently signed, so anyone may relay a list."""

    schema_version: Literal["autheo.revocation-list/v2"] = "autheo.revocation-list/v2"
    source: Annotated[str, Field(max_length=128)] = ""
    generated_at: Timestamp
    records: list[Revocation] = Field(default_factory=list, max_length=10000)


class Invocation(AliasModel):
    """Invoker-signed request to use the capability at the end of the embedded delegation chain."""

    type: Literal["AutheoInvocation"]
    schema_version: Literal["autheo.invocation/v2"] = "autheo.invocation/v2"
    id: Identifier
    invoker: Did
    environment: Identifier
    action: Scope
    resource: Identifier
    tool: ToolName | None = None
    amount_minor: Minor = 0
    asset: AssetId = "DEMO"
    created: DateTime
    expires: DateTime
    capability: list[Delegation] = Field(min_length=1, max_length=MAX_CHAIN_LENGTH)
    proof: DataIntegrityProof

    @model_validator(mode="after")
    def purpose(self):
        if self.proof.proofPurpose != "capabilityInvocation":
            raise ValueError("invocations are signed with proofPurpose capabilityInvocation")
        return self


class ChainLink(StrictModel):
    id: Urn
    digest: Hex64
    issuer: Did
    subject: Did


class ReceiptV2(AliasModel):
    """Environment-signed, hash-linked record of a decision or an accepted revocation."""

    type: Literal["AutheoReceipt"]
    schema_version: Literal["autheo.receipt/v2"] = "autheo.receipt/v2"
    id: Urn
    issuer: Did
    environment: Identifier
    sequence: Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]
    previous_hash: Hex64
    recorded_at: Timestamp
    kind: Literal["decision", "revocation"]
    decision: Literal["allow", "escalate", "block", "recorded"]
    reasons: list[ReasonCode] = Field(max_length=64)
    document_digest: Hex64
    request_id: Identifier | None = None
    invoker: Did | None = None
    root: Did | None = None
    chain: list[ChainLink] = Field(default_factory=list, max_length=MAX_CHAIN_LENGTH)
    action: Scope | None = None
    resource: Identifier | None = None
    tool: ToolName | None = None
    amount_minor: Minor = 0
    asset: AssetId | None = None
    policy_id: Identifier | None = None
    policy_digest: Hex64 | None = None
    reference: Urn | None = None
    executed: Literal[False] = False
    simulation_only: Literal[True] = True
    proof: DataIntegrityProof

    @model_validator(mode="after")
    def purpose(self):
        if self.proof.proofPurpose != "assertionMethod":
            raise ValueError("receipts are signed with proofPurpose assertionMethod")
        return self


class Bundle(StrictModel):
    """Everything an offline verifier needs: receipt, invocation (with chain) and known revocations."""

    schema_version: Literal["autheo.bundle/v2"] = "autheo.bundle/v2"
    receipt: ReceiptV2
    invocation: Invocation
    revocations: list[Revocation] = Field(default_factory=list, max_length=1000)


class LedgerExportV2(StrictModel):
    schema_version: Literal["autheo.ledger-export/v2"] = "autheo.ledger-export/v2"
    environment: Identifier
    issuer: Did
    head: Hex64
    receipts: list[ReceiptV2] = Field(max_length=100000)


class VerificationMethod(StrictModel):
    id: DidUrl
    type: Literal["Multikey"]
    controller: Did
    publicKeyMultibase: Annotated[str, StringConstraints(pattern=r"^z[1-9A-HJ-NP-Za-km-z]{40,60}$", strict=True)]


class DidKeyDocument(AliasModel):
    """DID document produced for a did:key (did:key Document Creation Algorithm, Multikey form)."""

    context: list[str] = Field(alias="@context", min_length=1)
    id: Did
    verificationMethod: list[VerificationMethod] = Field(min_length=1, max_length=2)
    authentication: list[DidUrl]
    assertionMethod: list[DidUrl]
    capabilityDelegation: list[DidUrl]
    capabilityInvocation: list[DidUrl]
    keyAgreement: list[DidUrl] | None = None
