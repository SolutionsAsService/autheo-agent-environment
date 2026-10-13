"""Permissionless capability delegation between DIDs (Autheo v2).

A delegation is a W3C VC 2.0 credential (type AutheoDelegation) signed by its
issuer DID with an eddsa-jcs-2022 Data Integrity proof (proofPurpose
capabilityDelegation). A chain is an ordered list [root, ..., leaf] in which each
link names its parent by id AND by the JCS SHA-256 digest of the complete parent
credential, and is issued by the parent's subject. Each link may only narrow its
parent (attenuation). An invocation signed by the leaf subject embeds the whole
chain, so a verifier needs nothing but the documents and the DIDs - no registry,
issuer service or network (did:key resolves locally).

Revocation is a signed record by a DID that is entitled to revoke the link (the
issuer of the link or of any ancestor link, or the link's own subject renouncing
it). Records are self-verifying and can be relayed by anyone (revocation lists,
ledger exports, gossip). Normative text: docs/SPEC-DID.md.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from uuid import uuid4

from pydantic import ValidationError

from .data_integrity import ProofError, add_proof, format_time, parse_time, verify_proof
from .did import DidSigner, Resolver
from .jcs import jcs_digest
from .models_v2 import (
    MAX_CHAIN_LENGTH,
    MAX_DELEGATION_SECONDS,
    MAX_INVOCATION_SECONDS,
    VC_CONTEXT,
    Capability,
    Delegation,
    Invocation,
    Revocation,
)

CLOCK_SKEW_SECONDS = 2
# Failures that mean "these documents are not what they claim to be" (rejected, never recorded)...
AUTHENTICITY_ERRORS = frozenset({"malformed", "bad_signature", "broken_link", "chain_too_long", "invoker_mismatch"})
# ...versus "authentic, but they do not authorise this now" (recorded as a block decision).
AUTHORIZATION_ERRORS = frozenset({"attenuation_violation", "depth_exceeded", "not_yet_valid", "expired", "revoked",
                                  "untrusted_root"})


def new_urn() -> str:
    return f"urn:uuid:{uuid4()}"


def document_digest(document: dict) -> str:
    """v2 digest: lowercase hex SHA-256 of the RFC 8785 JCS bytes of the complete document."""
    return jcs_digest(document)


# ---------------------------------------------------------------------- attenuation
def pattern_matches(pattern: str, value: str | None) -> bool:
    if value is None:
        return False
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def pattern_covers(parents: list[str], child: str) -> bool:
    """True when every value matched by child is matched by some parent pattern."""
    for parent in parents:
        if parent == "*":
            return True
        if parent.endswith("*"):
            if child.removesuffix("*").startswith(parent[:-1]):
                return True
        elif child == parent:
            return True
    return False


def attenuation_problems(parent: Capability, child: Capability) -> list[str]:
    """Every way in which child is NOT a narrowing of parent (empty list = valid attenuation)."""
    problems = []
    for name in ("environments", "resources", "tools"):
        for pattern in getattr(child, name):
            if not pattern_covers(getattr(parent, name), pattern):
                problems.append(f"{name}: {pattern} is not within the parent grant")
    for scope in child.scopes:
        if scope not in parent.scopes:
            problems.append(f"scopes: {scope} is not granted by the parent")
    if child.asset != parent.asset:
        problems.append(f"asset: {child.asset} differs from parent {parent.asset}")
    for name in ("per_action_minor", "total_budget_minor", "approval_threshold_minor"):
        if getattr(child, name) > getattr(parent, name):
            problems.append(f"{name}: {getattr(child, name)} exceeds parent {getattr(parent, name)}")
    return problems


def capability_problems(capability: Capability, *, environment: str, action: str, resource: str,
                        tool: str | None, amount_minor: int, asset: str = "DEMO") -> list[tuple[str, str]]:
    """Static checks of one request against a capability: [(reason code, detail)]; empty = within grant."""
    problems = []
    if not any(pattern_matches(p, environment) for p in capability.environments):
        problems.append(("environment_denied", f"environment {environment} is not delegated"))
    if action not in capability.scopes:
        problems.append(("scope_denied", f"action {action} is not delegated"))
    if not any(pattern_matches(p, resource) for p in capability.resources):
        problems.append(("resource_denied", f"resource {resource} is not delegated"))
    if action == "tool.invoke" and tool is None:
        problems.append(("tool_required", "tool.invoke requires a tool name"))
    elif tool is not None and not any(pattern_matches(p, tool) for p in capability.tools):
        problems.append(("tool_denied", f"tool {tool} is not delegated"))
    if asset != capability.asset:
        problems.append(("asset_mismatch", f"amount is in {asset}, the grant is in {capability.asset}"))
    if amount_minor > capability.per_action_minor:
        problems.append(("per_action_limit", f"{amount_minor} exceeds per-action limit {capability.per_action_minor}"))
    return problems


# ---------------------------------------------------------------------- issuing
def issue_delegation(signer: DidSigner, subject: str, capability: Capability | dict, *, valid_from: int,
                     valid_until: int, parent: dict | None = None, delegation_id: str | None = None,
                     created: int | None = None) -> dict:
    """Sign a delegation from signer.did to subject. Refuses to sign anything that is not an attenuation."""
    capability = capability if isinstance(capability, Capability) else Capability.model_validate(capability)
    if not 0 < valid_until - valid_from <= MAX_DELEGATION_SECONDS:
        raise ValueError(f"delegation validity must be 1..{MAX_DELEGATION_SECONDS} seconds")
    subject_body = {"id": subject, "schema_version": "autheo.delegation/v2",
                    "capability": capability.model_dump(mode="json")}
    if parent is not None:
        parent_model = Delegation.model_validate(parent)
        if parent_model.credentialSubject.id != signer.did:
            raise ValueError("only the subject of the parent delegation can sub-delegate it")
        problems = attenuation_problems(parent_model.credentialSubject.capability, capability)
        parent_capability = parent_model.credentialSubject.capability
        if parent_capability.max_delegation_depth < 1:
            problems.append("parent delegation does not allow further delegation")
        elif capability.max_delegation_depth > parent_capability.max_delegation_depth - 1:
            problems.append("max_delegation_depth must be lower than the parent's")
        if valid_from < parse_time(parent_model.validFrom) or valid_until > parse_time(parent_model.validUntil):
            problems.append("validity window must lie within the parent's")
        if problems:
            raise ValueError("not an attenuation of the parent: " + "; ".join(problems))
        subject_body["parent"] = {"id": parent_model.id, "digest": document_digest(parent)}
    document = {
        "@context": [VC_CONTEXT],
        "type": ["VerifiableCredential", "AutheoDelegation"],
        "id": delegation_id or new_urn(),
        "issuer": signer.did,
        "validFrom": format_time(valid_from),
        "validUntil": format_time(valid_until),
        "credentialSubject": subject_body,
    }
    signed = add_proof(document, signer, "capabilityDelegation", valid_from if created is None else created)
    Delegation.model_validate(signed)
    return signed


def issue_revocation(signer: DidSigner, target: dict, *, revoked_at: int, reason: str = "revoked",
                     revocation_id: str | None = None) -> dict:
    model = Delegation.model_validate(target)
    document = {
        "type": "AutheoRevocation",
        "schema_version": "autheo.revocation/v2",
        "id": revocation_id or new_urn(),
        "issuer": signer.did,
        "target": {"id": model.id, "digest": document_digest(target)},
        "revoked_at": format_time(revoked_at),
        "reason": reason,
    }
    signed = add_proof(document, signer, "assertionMethod", revoked_at)
    Revocation.model_validate(signed)
    return signed


def issue_invocation(signer: DidSigner, chain: list[dict], *, request_id: str, environment: str, action: str,
                     resource: str, tool: str | None = None, amount_minor: int = 0, created: int,
                     ttl: int = 60, asset: str = "DEMO") -> dict:
    if not 0 < ttl <= MAX_INVOCATION_SECONDS:
        raise ValueError(f"invocation lifetime must be 1..{MAX_INVOCATION_SECONDS} seconds")
    document = {
        "type": "AutheoInvocation",
        "schema_version": "autheo.invocation/v2",
        "id": request_id,
        "invoker": signer.did,
        "environment": environment,
        "action": action,
        "resource": resource,
        "amount_minor": amount_minor,
        "asset": asset,
        "created": format_time(created),
        "expires": format_time(created + ttl),
        "capability": list(chain),
    }
    if tool is not None:
        document["tool"] = tool
    signed = add_proof(document, signer, "capabilityInvocation", created)
    Invocation.model_validate(signed)
    return signed


# ---------------------------------------------------------------------- verification
@dataclass(frozen=True)
class ChainError:
    index: int
    code: str
    detail: str

    def to_dict(self) -> dict:
        return {"index": self.index, "code": self.code, "detail": self.detail[:300]}


@dataclass
class ChainResult:
    at: int
    errors: list[ChainError] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)
    root: str | None = None
    leaf: str | None = None
    capability: Capability | None = None
    ignored_revocations: int = 0

    @property
    def authentic(self) -> bool:
        return not any(e.code in AUTHENTICITY_ERRORS for e in self.errors)

    @property
    def valid(self) -> bool:
        return not self.errors

    def reasons(self) -> list[str]:
        seen = []
        for error in self.errors:
            reason = f"delegation_{error.code}:{error.index}"
            if reason not in seen:
                seen.append(reason)
        return seen

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "authentic": self.authentic,
            "verified_at": self.at,
            "root": self.root,
            "leaf": self.leaf,
            "depth": len(self.links),
            "links": self.links,
            "capability": self.capability.model_dump(mode="json") if self.capability else None,
            "errors": [e.to_dict() for e in self.errors],
            "ignored_revocations": self.ignored_revocations,
        }


def verify_revocation(record: dict, resolver: Resolver) -> Revocation:
    """Verify a revocation record's structure and signature; raises ProofError."""
    try:
        model = Revocation.model_validate(record)
    except ValidationError as error:
        raise ProofError("malformed", "revocation record does not match autheo.revocation/v2") from error
    proof = verify_proof(record, resolver, "assertionMethod")
    if proof.controller != model.issuer:
        raise ProofError("bad_signature", "revocation proof is not by its issuer")
    return model


def _usable_revocations(revocations: Iterable[dict], resolver: Resolver) -> tuple[dict[str, list[Revocation]], int]:
    by_target: dict[str, list[Revocation]] = {}
    ignored = 0
    for record in revocations:
        try:
            model = verify_revocation(record, resolver)
        except (ProofError, ValueError):
            ignored += 1
            continue
        by_target.setdefault(model.target.id, []).append(model)
    return by_target, ignored


def verify_chain(chain, *, resolver: Resolver, at: int, trusted_roots: Iterable[str] | None = None,
                 revocations: Iterable[dict] = (), skew: int = CLOCK_SKEW_SECONDS) -> ChainResult:
    """Verify a delegation chain [root, ..., leaf] at time "at" (epoch seconds). Never raises on bad input."""
    result = ChainResult(at=at)
    roots = None if trusted_roots is None else set(trusted_roots)
    if not isinstance(chain, list) or not chain:
        result.errors.append(ChainError(0, "malformed", "chain must be a non-empty list"))
        return result
    if len(chain) > MAX_CHAIN_LENGTH:
        result.errors.append(ChainError(0, "chain_too_long", f"at most {MAX_CHAIN_LENGTH} links"))
        return result
    parsed: list[tuple[dict, Delegation, str] | None] = []
    for index, raw in enumerate(chain):
        try:
            model = Delegation.model_validate(raw)
        except ValidationError as error:
            fields = sorted({".".join(str(p) for p in e["loc"]) for e in error.errors()})
            result.errors.append(ChainError(index, "malformed", ", ".join(fields)))
            parsed.append(None)
            continue
        try:
            proof = verify_proof(raw, resolver, "capabilityDelegation")
            if proof.controller != model.issuer:
                raise ProofError("bad_signature", f"proof is by {proof.controller}, issuer is {model.issuer}")
        except ProofError as error:
            result.errors.append(ChainError(index, "bad_signature", str(error)))
            parsed.append(None)
            continue
        parsed.append((raw, model, document_digest(raw)))

    usable, result.ignored_revocations = _usable_revocations(revocations, resolver)
    issuers: list[str] = []
    for index, entry in enumerate(parsed):
        if entry is None:
            issuers.append("")
            continue
        raw, model, digest = entry
        subject = model.credentialSubject
        issuers.append(model.issuer)
        valid_from, valid_until = parse_time(model.validFrom), parse_time(model.validUntil)
        result.links.append({"index": index, "id": model.id, "digest": digest, "issuer": model.issuer,
                             "subject": subject.id, "valid_from": model.validFrom, "valid_until": model.validUntil})
        if not 0 < valid_until - valid_from <= MAX_DELEGATION_SECONDS:
            result.errors.append(ChainError(index, "malformed", "invalid validity window"))
        if index == 0:
            if subject.parent is not None:
                result.errors.append(ChainError(index, "broken_link", "the root delegation must not name a parent"))
            if roots is not None and model.issuer not in roots:
                result.errors.append(ChainError(index, "untrusted_root", f"{model.issuer} is not a trusted root"))
        else:
            previous = parsed[index - 1]
            if previous is None:
                result.errors.append(ChainError(index, "broken_link", "parent link could not be verified"))
            else:
                _, parent, parent_digest = previous
                if subject.parent is None or subject.parent.id != parent.id or subject.parent.digest != parent_digest:
                    result.errors.append(ChainError(index, "broken_link", "parent id/digest does not match link "
                                                    f"{index - 1}"))
                if model.issuer != parent.credentialSubject.id:
                    result.errors.append(ChainError(index, "broken_link", "issuer is not the subject of the parent"))
                for problem in attenuation_problems(parent.credentialSubject.capability, subject.capability):
                    result.errors.append(ChainError(index, "attenuation_violation", problem))
                if valid_from < parse_time(parent.validFrom) or valid_until > parse_time(parent.validUntil):
                    result.errors.append(ChainError(index, "attenuation_violation", "validity window widened"))
                parent_depth = parent.credentialSubject.capability.max_delegation_depth
                if parent_depth < 1:
                    result.errors.append(ChainError(index, "depth_exceeded", "parent does not allow sub-delegation"))
                elif subject.capability.max_delegation_depth > parent_depth - 1:
                    result.errors.append(ChainError(index, "depth_exceeded", "max_delegation_depth not reduced"))
        if valid_from > at + skew:
            result.errors.append(ChainError(index, "not_yet_valid", f"valid from {model.validFrom}"))
        if at >= valid_until:
            result.errors.append(ChainError(index, "expired", f"expired at {model.validUntil}"))
        entitled = {i for i in issuers if i} | {subject.id}
        for record in usable.get(model.id, []):
            if record.target.digest == digest and record.issuer in entitled and parse_time(record.revoked_at) <= at:
                result.errors.append(ChainError(index, "revoked", f"{record.id} by {record.issuer}"))
                break
    if parsed[0] is not None:
        result.root = parsed[0][1].issuer
    if parsed[-1] is not None:
        result.leaf = parsed[-1][1].credentialSubject.id
        result.capability = parsed[-1][1].credentialSubject.capability
    return result


@dataclass
class InvocationResult:
    invocation: Invocation
    chain: ChainResult
    digest: str
    created: int
    expires: int


def verify_invocation(raw: dict, *, resolver: Resolver, at: int, trusted_roots: Iterable[str] | None = None,
                      revocations: Iterable[dict] = (), skew: int = CLOCK_SKEW_SECONDS) -> InvocationResult:
    """Verify an invocation's own proof and validity (raises ProofError), then its chain (in the result)."""
    try:
        model = Invocation.model_validate(raw)
    except ValidationError as error:
        fields = sorted({".".join(str(p) for p in e["loc"]) for e in error.errors()})[:8]
        raise ProofError("malformed", "invocation: " + ", ".join(fields)) from error
    proof = verify_proof(raw, resolver, "capabilityInvocation")
    if proof.controller != model.invoker:
        raise ProofError("bad_signature", "invocation proof is not by the invoker")
    created, expires = parse_time(model.created), parse_time(model.expires)
    if not 0 < expires - created <= MAX_INVOCATION_SECONDS:
        raise ProofError("malformed", f"invocation lifetime must be 1..{MAX_INVOCATION_SECONDS} seconds")
    if at >= expires:
        raise ProofError("expired", f"invocation expired at {model.expires}")
    if created > at + skew:
        raise ProofError("not_yet_valid", f"invocation created at {model.created}")
    chain = verify_chain(raw["capability"], resolver=resolver, at=at, trusted_roots=trusted_roots,
                         revocations=revocations, skew=skew)
    if chain.leaf is not None and chain.leaf != model.invoker:
        chain.errors.append(ChainError(len(raw["capability"]) - 1, "invoker_mismatch",
                                       "the invoker is not the subject of the leaf delegation"))
    return InvocationResult(model, chain, document_digest(raw), created, expires)
