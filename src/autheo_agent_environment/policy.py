"""Declarative, deterministic policy evaluation (autheo.policy/v1).

A policy is operator configuration (YAML or JSON), never agent input. It can only
NARROW what a signed mandate already allows: it adds scope/tool/resource allow and
deny lists, windowed budgets, rate limits, time windows and escalation rules.
Evaluation is a pure function of (policy, mandate, request, revocation flag,
prior receipts, clock) and returns a Decision with a per-check explanation.

Outcome precedence is block > escalate > allow. With the built-in default policy
the decisions and reason codes are identical to the 0.1 mandate-only simulator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field, StringConstraints, field_validator, model_validator

from .canonical import digest
from .models import (
    BudgetState,
    Decision,
    Explanation,
    Identifier,
    Mandate,
    Minor,
    Request,
    StrictModel,
)

MAX_POLICY_BYTES = 262144
Pattern = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9*?:._/\[\]!-]{1,128}$", strict=True)]
Seconds = Annotated[int, Field(strict=True, ge=1, le=31_536_000)]
ClockTime = Annotated[str, StringConstraints(pattern=r"^([01][0-9]|2[0-3]):[0-5][0-9]$", strict=True)]
Day = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DAYS: tuple[str, ...] = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _matches(value: str | None, patterns: list[str]) -> bool:
    return value is not None and any(fnmatchcase(value, pattern) for pattern in patterns)


def _applies(patterns: list[str], value: str | None) -> bool:
    """An empty filter applies to everything; otherwise the value must match a pattern."""
    return not patterns or _matches(value, patterns)


class MatchSet(StrictModel):
    """Glob allow/deny lists. Deny wins. An empty allow list means "no extra restriction"."""

    allow: list[Pattern] = Field(default_factory=list, max_length=200)
    deny: list[Pattern] = Field(default_factory=list, max_length=200)


class BudgetRule(StrictModel):
    id: Identifier
    limit_minor: Minor
    window_seconds: Seconds | None = None
    actions: list[Pattern] = Field(default_factory=list, max_length=50)
    tools: list[Pattern] = Field(default_factory=list, max_length=50)


class RateLimit(StrictModel):
    id: Identifier
    max_requests: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
    window_seconds: Seconds
    actions: list[Pattern] = Field(default_factory=list, max_length=50)
    tools: list[Pattern] = Field(default_factory=list, max_length=50)


class TimeWindow(StrictModel):
    id: Identifier
    timezone: str = Field(default="UTC", max_length=64)
    days: list[Day] = Field(default_factory=lambda: list(DAYS), min_length=1, max_length=7)
    start: ClockTime
    end: ClockTime
    outside: Literal["block", "escalate"] = "block"
    actions: list[Pattern] = Field(default_factory=list, max_length=50)
    tools: list[Pattern] = Field(default_factory=list, max_length=50)

    @field_validator("timezone")
    @classmethod
    def known_timezone(cls, value: str) -> str:
        _zone(value)
        return value

    @model_validator(mode="after")
    def non_empty(self):
        if self.start == self.end:
            raise ValueError("time window start and end must differ")
        return self

    def contains(self, moment: datetime) -> bool:
        local = moment.astimezone(_zone(self.timezone))
        minute = local.hour * 60 + local.minute
        start = int(self.start[:2]) * 60 + int(self.start[3:])
        end = int(self.end[:2]) * 60 + int(self.end[3:])
        day = DAYS[local.weekday()]
        if start < end:
            return day in self.days and start <= minute < end
        # Overnight window: the part after midnight belongs to the previous day's window.
        if minute >= start:
            return day in self.days
        previous_day = DAYS[(local.weekday() - 1) % 7]
        return minute < end and previous_day in self.days


class EscalationRule(StrictModel):
    id: Identifier
    amount_minor_gt: Minor | None = None
    actions: list[Pattern] = Field(default_factory=list, max_length=50)
    tools: list[Pattern] = Field(default_factory=list, max_length=50)
    resources: list[Pattern] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def has_condition(self):
        if self.amount_minor_gt is None and not (self.actions or self.tools or self.resources):
            raise ValueError("escalation rule needs at least one condition")
        return self

    def triggered(self, request: Request) -> bool:
        return (
            (self.amount_minor_gt is None or request.amount_minor > self.amount_minor_gt)
            and (not self.actions or _matches(request.action, self.actions))
            and (not self.tools or _matches(request.tool, self.tools))
            and (not self.resources or _matches(request.resource, self.resources))
        )


class PolicyDocument(StrictModel):
    schema_version: Literal["autheo.policy/v1"] = "autheo.policy/v1"
    policy_id: Identifier
    description: str = Field(default="", max_length=500)
    scopes: MatchSet = Field(default_factory=MatchSet)
    tools: MatchSet = Field(default_factory=MatchSet)
    resources: MatchSet = Field(default_factory=MatchSet)
    budgets: list[BudgetRule] = Field(default_factory=list, max_length=50)
    rate_limits: list[RateLimit] = Field(default_factory=list, max_length=50)
    time_windows: list[TimeWindow] = Field(default_factory=list, max_length=20)
    escalations: list[EscalationRule] = Field(default_factory=list, max_length=50)
    use_mandate_approval_threshold: bool = True

    @model_validator(mode="after")
    def unique_rule_ids(self):
        ids = [r.id for r in (*self.budgets, *self.rate_limits, *self.time_windows, *self.escalations)]
        if len(ids) != len(set(ids)):
            raise ValueError("policy rule ids must be unique")
        return self

    @property
    def digest(self) -> str:
        return digest(self.model_dump(mode="json"))


DEFAULT_POLICY = PolicyDocument(
    policy_id="policy:mandate-only",
    description="Mandate limits only; identical outcomes to the 0.1 reference simulator.",
)


def _zone(name: str):
    if name == "UTC":
        return UTC
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError(f"unknown timezone {name!r}") from error


def parse_policy(data) -> PolicyDocument:
    return PolicyDocument.model_validate(data)


def load_policy(path: Path) -> PolicyDocument:
    path = Path(path)
    if path.stat().st_size > MAX_POLICY_BYTES:
        raise ValueError("Policy file exceeds size limit")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        import yaml

        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return parse_policy(data)


@dataclass(frozen=True)
class PriorEvent:
    """A previously recorded simulation receipt for the same mandate."""

    decision: str
    amount_minor: int
    action: str | None
    tool: str | None
    recorded_at: int


def _check(explanation, check, outcome, detail):
    explanation.append(Explanation(check=check, outcome=outcome, detail=detail[:300]))


def evaluate(
    *,
    policy: PolicyDocument,
    mandate: Mandate,
    mandate_id: str,
    request: Request,
    revoked: bool,
    history: list[PriorEvent],
    now: int,
) -> Decision:
    """Deterministically evaluate one request. Runs every check so the explanation is complete."""
    blocks: list[str] = []
    escalations: list[str] = []
    explanation: list[Explanation] = []
    allowed = [e for e in history if e.decision == "allow"]
    spent = sum(e.amount_minor for e in allowed)

    def gate(check, failed, reason, detail_ok, detail_fail):
        if failed:
            blocks.append(reason)
        _check(explanation, check, "fail" if failed else "pass", detail_fail if failed else detail_ok)

    # --- mandate (0.1-compatible, fixed order) ---------------------------------
    gate("mandate.revocation", revoked, "revoked", "passport and mandate are not revoked",
         "passport or mandate is revoked")
    gate("mandate.scope", request.action not in mandate.scopes, "scope_denied",
         f"action {request.action} is granted", f"action {request.action} is not granted by the mandate")
    gate("mandate.resource", request.resource not in mandate.resources, "resource_denied",
         f"resource {request.resource} is granted", f"resource {request.resource} is not granted")
    gate("mandate.per_action_limit", request.amount_minor > mandate.per_action_minor, "per_action_limit",
         f"{request.amount_minor} <= per-action limit {mandate.per_action_minor}",
         f"{request.amount_minor} exceeds per-action limit {mandate.per_action_minor}")
    gate("mandate.total_budget", spent + request.amount_minor > mandate.total_budget_minor,
         "total_budget_limit",
         f"spent {spent} + {request.amount_minor} <= total {mandate.total_budget_minor}",
         f"spent {spent} + {request.amount_minor} exceeds total {mandate.total_budget_minor}")
    if request.action == "tool.invoke" and request.tool is None:
        gate("mandate.tool", True, "tool_required", "", "tool.invoke requires a tool name")
    elif request.tool is None:
        _check(explanation, "mandate.tool", "not_applicable", "request names no tool")
    else:
        gate("mandate.tool", request.tool not in mandate.tools, "tool_denied",
             f"tool {request.tool} is granted", f"tool {request.tool} is not granted by the mandate")

    # --- declarative policy (can only narrow) ----------------------------------
    for check, rules, value, reason in (
        ("policy.scopes", policy.scopes, request.action, "policy_scope_denied"),
        ("policy.tools", policy.tools, request.tool, "policy_tool_denied"),
        ("policy.resources", policy.resources, request.resource, "policy_resource_denied"),
    ):
        if not rules.allow and not rules.deny:
            _check(explanation, check, "not_applicable", "no allow/deny list configured")
        elif value is None:
            _check(explanation, check, "not_applicable", "request has no value for this list")
        elif _matches(value, rules.deny):
            gate(check, True, reason, "", f"{value} matches a deny pattern")
        elif rules.allow and not _matches(value, rules.allow):
            gate(check, True, reason, "", f"{value} matches no allow pattern")
        else:
            gate(check, False, reason, f"{value} permitted by policy list", "")

    for rule in policy.budgets:
        check = f"policy.budget:{rule.id}"
        if not (_applies(rule.actions, request.action) and _applies(rule.tools, request.tool)):
            _check(explanation, check, "not_applicable", "budget filter does not match request")
            continue
        used = sum(
            e.amount_minor
            for e in allowed
            if _applies(rule.actions, e.action)
            and _applies(rule.tools, e.tool)
            and (rule.window_seconds is None or e.recorded_at > now - rule.window_seconds)
        )
        window = "mandate lifetime" if rule.window_seconds is None else f"last {rule.window_seconds}s"
        gate(check, used + request.amount_minor > rule.limit_minor, f"budget_exhausted:{rule.id}",
             f"{used} + {request.amount_minor} <= {rule.limit_minor} ({window})",
             f"{used} + {request.amount_minor} exceeds {rule.limit_minor} ({window})")

    for rule in policy.rate_limits:
        check = f"policy.rate_limit:{rule.id}"
        if not (_applies(rule.actions, request.action) and _applies(rule.tools, request.tool)):
            _check(explanation, check, "not_applicable", "rate-limit filter does not match request")
            continue
        count = sum(
            1
            for e in history
            if e.decision in {"allow", "escalate"}
            and _applies(rule.actions, e.action)
            and _applies(rule.tools, e.tool)
            and e.recorded_at > now - rule.window_seconds
        )
        gate(check, count + 1 > rule.max_requests, f"rate_limited:{rule.id}",
             f"{count + 1} <= {rule.max_requests} requests in {rule.window_seconds}s",
             f"{count + 1} exceeds {rule.max_requests} requests in {rule.window_seconds}s")

    moment = datetime.fromtimestamp(now, UTC)
    for rule in policy.time_windows:
        check = f"policy.time_window:{rule.id}"
        if not (_applies(rule.actions, request.action) and _applies(rule.tools, request.tool)):
            _check(explanation, check, "not_applicable", "time-window filter does not match request")
        elif rule.contains(moment):
            _check(explanation, check, "pass", f"inside {rule.start}-{rule.end} {rule.timezone}")
        elif rule.outside == "block":
            gate(check, True, f"outside_time_window:{rule.id}", "",
                 f"outside {rule.start}-{rule.end} {rule.timezone}")
        else:
            escalations.append(f"outside_time_window:{rule.id}")
            _check(explanation, check, "escalate", f"outside {rule.start}-{rule.end} {rule.timezone}")

    if policy.use_mandate_approval_threshold:
        if request.amount_minor > mandate.approval_threshold_minor:
            escalations.insert(0, "human_review_required")
            _check(explanation, "mandate.approval_threshold", "escalate",
                   f"{request.amount_minor} exceeds review threshold {mandate.approval_threshold_minor}")
        else:
            _check(explanation, "mandate.approval_threshold", "pass",
                   f"{request.amount_minor} <= review threshold {mandate.approval_threshold_minor}")
    for rule in policy.escalations:
        check = f"policy.escalation:{rule.id}"
        if rule.triggered(request):
            escalations.append(f"policy_escalation:{rule.id}")
            _check(explanation, check, "escalate", "escalation rule matched")
        else:
            _check(explanation, check, "pass", "escalation rule did not match")

    if blocks:
        outcome, reasons = "block", blocks
    elif escalations:
        outcome, reasons = "escalate", escalations
    else:
        outcome, reasons = "allow", ["within_demo_policy"]
    reserved = request.amount_minor if outcome == "allow" else 0
    return Decision(
        request_id=request.request_id,
        agent_id=request.agent_id,
        environment=request.environment,
        mandate_id=mandate_id,
        action=request.action,
        resource=request.resource,
        tool=request.tool,
        amount_minor=request.amount_minor,
        decision=outcome,
        reasons=reasons,
        explanation=explanation,
        policy_id=policy.policy_id,
        policy_digest=policy.digest,
        request_digest=digest(request.model_dump()),
        budget=BudgetState(
            total_budget_minor=mandate.total_budget_minor,
            spent_minor=spent + reserved,
            remaining_minor=max(0, mandate.total_budget_minor - spent - reserved),
        ),
        evaluated_at=now,
    )
