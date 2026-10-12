import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from autheo_agent_environment.models import Mandate, Request
from autheo_agent_environment.policy import (
    DEFAULT_POLICY,
    PolicyDocument,
    PriorEvent,
    TimeWindow,
    evaluate,
    load_policy,
    parse_policy,
)

NOW = int(datetime(2026, 10, 12, 15, 0, tzinfo=UTC).timestamp())  # Monday 15:00 UTC

MANDATE = Mandate(
    agent_id="agent:one",
    owner_id="owner:one",
    environment="env:one",
    scopes=["tool.invoke", "compute.simulate", "file.read"],
    resources=["repo:one", "listing:one"],
    tools=["git.status", "git.diff", "shell.exec"],
    per_action_minor=80,
    total_budget_minor=100,
    approval_threshold_minor=50,
)


def request(**changes):
    fields = dict(
        request_id="req:x", agent_id="agent:one", environment="env:one", mandate_id="m-1",
        action="tool.invoke", resource="repo:one", tool="git.status", amount_minor=10,
    )
    fields.update(changes)
    return Request(**fields)


def run(policy=DEFAULT_POLICY, history=(), revoked=False, now=NOW, **changes):
    return evaluate(policy=policy, mandate=MANDATE, mandate_id="m-1", request=request(**changes),
                    revoked=revoked, history=list(history), now=now)


def event(amount, decision="allow", age=0, action="tool.invoke", tool="git.status"):
    return PriorEvent(decision=decision, amount_minor=amount, action=action, tool=tool, recorded_at=NOW - age)


def policy(**fields):
    return parse_policy({"policy_id": "policy:test", **fields})


def checks(decision):
    return {item.check: item.outcome for item in decision.explanation}


def test_default_policy_reproduces_01_outcomes_and_reasons():
    assert run().reasons == ["within_demo_policy"] and run().decision == "allow"
    assert run(amount_minor=51).reasons == ["human_review_required"]
    blocked = run(amount_minor=81, history=[event(40)])
    assert blocked.decision == "block" and blocked.reasons == ["per_action_limit", "total_budget_limit"]
    assert run(revoked=True).reasons == ["revoked"]
    assert run(action="chain.read").reasons == ["scope_denied"]
    assert run(resource="repo:other").reasons == ["resource_denied"]
    assert run(action="compute.simulate", tool=None).decision == "allow"


def test_decision_shape_is_not_a_capability():
    decision = run()
    assert decision.executed is False and decision.is_capability is False
    assert decision.policy_digest == DEFAULT_POLICY.digest
    assert decision.budget.spent_minor == 10 and decision.budget.remaining_minor == 90
    assert checks(decision)["mandate.scope"] == "pass"
    assert checks(decision)["policy.tools"] == "not_applicable"


def test_tool_rules_in_mandate():
    assert run(tool=None).reasons == ["tool_required"]
    assert run(tool="browser.open").reasons == ["tool_denied"]
    # A tool on a non-tool action still needs an exact mandate grant.
    assert run(action="file.read", tool="cat").reasons == ["tool_denied"]


def test_policy_lists_only_narrow_and_deny_wins():
    p = policy(tools={"allow": ["git.*"], "deny": ["git.diff"]}, scopes={"deny": ["file.*"]},
               resources={"allow": ["repo:*"]})
    assert run(p).decision == "allow"
    assert run(p, tool="git.diff").reasons == ["policy_tool_denied"]
    assert run(p, tool="shell.exec").reasons == ["policy_tool_denied"]
    assert run(p, action="file.read", tool=None).reasons == ["policy_scope_denied"]
    assert run(p, action="compute.simulate", tool=None, resource="listing:one").reasons == [
        "policy_resource_denied"
    ]
    # Policy allow-lists cannot widen the mandate.
    wide = policy(tools={"allow": ["*"]})
    assert run(wide, tool="browser.open").reasons == ["tool_denied"]


def test_windowed_and_lifetime_budgets_exhaust():
    p = policy(budgets=[
        {"id": "hourly", "limit_minor": 30, "window_seconds": 3600},
        {"id": "git-lifetime", "limit_minor": 60, "tools": ["git.*"]},
    ])
    assert run(p, history=[event(20, age=4000)]).decision == "allow"  # outside the hour
    exhausted = run(p, history=[event(25, age=10)])
    assert exhausted.decision == "block" and exhausted.reasons == ["budget_exhausted:hourly"]
    assert checks(exhausted)["policy.budget:hourly"] == "fail"
    lifetime = run(p, history=[event(25, age=5000), event(30, age=9000)])
    assert lifetime.reasons == ["budget_exhausted:git-lifetime"]
    # Escalated/blocked history consumes no budget.
    assert run(p, history=[event(25, decision="escalate"), event(25, decision="block")]).decision == "allow"
    unrelated = run(p, history=[event(25)], action="compute.simulate", tool=None)
    assert "budget_exhausted:git-lifetime" not in unrelated.reasons
    assert checks(unrelated)["policy.budget:git-lifetime"] == "not_applicable"


def test_rate_limits_count_allow_and_escalate_in_window():
    p = policy(rate_limits=[{"id": "burst", "max_requests": 2, "window_seconds": 60, "tools": ["git.*"]}])
    assert run(p, history=[event(1), event(1, age=120)]).decision == "allow"
    limited = run(p, history=[event(1), event(1, decision="escalate")])
    assert limited.reasons == ["rate_limited:burst"]
    assert run(p, history=[event(1), event(1, decision="block")]).decision == "allow"
    assert run(p, history=[event(1), event(1)], action="compute.simulate", tool=None).decision == "allow"


def test_time_windows_block_or_escalate_outside():
    office = {"id": "office", "start": "09:00", "end": "17:00", "days": ["mon", "tue", "wed", "thu", "fri"]}
    assert run(policy(time_windows=[office])).decision == "allow"
    night = NOW + 6 * 3600  # 21:00 UTC
    assert run(policy(time_windows=[office]), now=night).reasons == ["outside_time_window:office"]
    soft = policy(time_windows=[{**office, "outside": "escalate"}])
    assert run(soft, now=night).decision == "escalate"
    assert run(soft, now=night).reasons == ["outside_time_window:office"]
    denver = policy(time_windows=[{**office, "timezone": "America/Denver"}])
    assert run(denver).decision == "allow"  # 09:00 local
    assert run(denver, now=NOW - 3600).decision == "block"  # 08:00 local


def test_overnight_window_belongs_to_start_day():
    window = TimeWindow(id="night", start="22:00", end="06:00", days=["mon"])
    assert window.contains(datetime(2026, 10, 12, 23, 0, tzinfo=UTC))  # Monday night
    assert window.contains(datetime(2026, 10, 13, 5, 0, tzinfo=UTC))  # Tuesday early = Monday window
    assert not window.contains(datetime(2026, 10, 13, 23, 0, tzinfo=UTC))  # Tuesday night
    assert not window.contains(datetime(2026, 10, 12, 12, 0, tzinfo=UTC))


def test_escalation_rules_and_precedence():
    p = policy(escalations=[
        {"id": "big", "amount_minor_gt": 20},
        {"id": "shell", "tools": ["shell.*"]},
    ])
    assert run(p, amount_minor=21).reasons == ["policy_escalation:big"]
    assert run(p, tool="shell.exec").reasons == ["policy_escalation:shell"]
    both = run(p, amount_minor=60)
    assert both.reasons == ["human_review_required", "policy_escalation:big"]
    blocked = run(p, amount_minor=60, revoked=True)
    assert blocked.decision == "block" and blocked.reasons == ["revoked"]
    no_threshold = policy(use_mandate_approval_threshold=False)
    assert run(no_threshold, amount_minor=60).decision == "allow"


@pytest.mark.parametrize(
    "fields",
    [
        {"budgets": [{"id": "a", "limit_minor": 1}], "rate_limits": [{"id": "a", "max_requests": 1,
                                                                       "window_seconds": 1}]},
        {"time_windows": [{"id": "t", "start": "09:00", "end": "09:00"}]},
        {"time_windows": [{"id": "t", "start": "09:00", "end": "10:00", "timezone": "Mars/Base"}]},
        {"escalations": [{"id": "e"}]},
        {"unknown_field": True},
        {"tools": {"allow": ["bad pattern"]}},
        {"budgets": [{"id": "b", "limit_minor": 1.5}]},
    ],
)
def test_invalid_policies_are_rejected(fields):
    with pytest.raises(ValidationError):
        policy(**fields)


def test_load_yaml_and_json_policy_files(tmp_path):
    yaml_file = tmp_path / "policy.yaml"
    yaml_file.write_text("policy_id: policy:yaml\ntools:\n  deny: ['shell.*']\n")
    json_file = tmp_path / "policy.json"
    json_file.write_text(json.dumps({"policy_id": "policy:json", "tools": {"deny": ["shell.*"]}}))
    loaded_yaml, loaded_json = load_policy(yaml_file), load_policy(json_file)
    assert loaded_yaml.tools.deny == loaded_json.tools.deny == ["shell.*"]
    assert loaded_yaml.digest != loaded_json.digest  # policy_id differs
    assert PolicyDocument.model_validate(loaded_yaml.model_dump()).digest == loaded_yaml.digest
    big = tmp_path / "big.json"
    big.write_text(" " * 300_000)
    with pytest.raises(ValueError, match="size"):
        load_policy(big)
