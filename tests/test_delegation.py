"""Delegation chains: attenuation, verification, tampering, expiry, revocation, invocations."""

from __future__ import annotations

import copy

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from autheo_agent_environment.data_integrity import ProofError, add_proof, format_time
from autheo_agent_environment.delegation import (
    AUTHENTICITY_ERRORS,
    AUTHORIZATION_ERRORS,
    attenuation_problems,
    capability_problems,
    document_digest,
    issue_delegation,
    issue_invocation,
    issue_revocation,
    pattern_covers,
    pattern_matches,
    verify_chain,
    verify_invocation,
    verify_revocation,
)
from autheo_agent_environment.did import DidKey, Resolver
from autheo_agent_environment.models_v2 import VC_CONTEXT, Capability

T = 1_790_000_000
ROOT, AGENT, SUB, STRANGER = (DidKey.from_seed(bytes([i]) * 32) for i in (1, 2, 3, 4))
ROOT_CAP = dict(environments=["env:*"], scopes=["compute.simulate", "marketplace.read", "tool.invoke"],
                resources=["listing:*", "repo:jarvis"], tools=["git.*"], per_action_minor=80,
                total_budget_minor=100, approval_threshold_minor=50, max_delegation_depth=2)
AGENT_CAP = dict(environments=["env:research"], scopes=["compute.simulate", "tool.invoke"],
                 resources=["listing:demo-*", "repo:jarvis"], tools=["git.status"], per_action_minor=60,
                 total_budget_minor=80, approval_threshold_minor=40, max_delegation_depth=1)
SUB_CAP = dict(environments=["env:research"], scopes=["compute.simulate"], resources=["listing:demo-01"],
               per_action_minor=30, total_budget_minor=50, approval_threshold_minor=20, max_delegation_depth=0)


def chain3():
    d1 = issue_delegation(ROOT.signer, AGENT.did, ROOT_CAP, valid_from=T, valid_until=T + 7200)
    d2 = issue_delegation(AGENT.signer, SUB.did, AGENT_CAP, valid_from=T, valid_until=T + 3600, parent=d1)
    d3 = issue_delegation(SUB.signer, STRANGER.did, {**SUB_CAP}, valid_from=T, valid_until=T + 1800, parent=d2)
    return [d1, d2, d3]


def chain2():
    d1 = issue_delegation(ROOT.signer, AGENT.did, ROOT_CAP, valid_from=T, valid_until=T + 7200)
    d2 = issue_delegation(AGENT.signer, SUB.did, {**AGENT_CAP, "max_delegation_depth": 0}, valid_from=T,
                          valid_until=T + 3600, parent=d1)
    return [d1, d2]


def forge(signer, subject, capability, *, valid_from=T, valid_until=T + 3600, parent=None, digest=None):
    """Sign a delegation WITHOUT the issuing-side attenuation checks (what an attacker could do)."""
    body = {"id": subject, "schema_version": "autheo.delegation/v2",
            "capability": Capability.model_validate(capability).model_dump(mode="json")}
    if parent is not None:
        body["parent"] = {"id": parent["id"], "digest": digest or document_digest(parent)}
    document = {"@context": [VC_CONTEXT], "type": ["VerifiableCredential", "AutheoDelegation"],
                "id": "urn:uuid:00000000-0000-4000-8000-0000000000ff", "issuer": signer.did,
                "validFrom": format_time(valid_from), "validUntil": format_time(valid_until),
                "credentialSubject": body}
    return add_proof(document, signer, "capabilityDelegation", valid_from)


def codes(result):
    return [(e.index, e.code) for e in result.errors]


def verify(chain, at=T + 60, roots=(ROOT.did,), revocations=()):
    return verify_chain(chain, resolver=Resolver(), at=at, trusted_roots=roots, revocations=revocations)


# ---------------------------------------------------------------------- patterns and attenuation
@pytest.mark.parametrize("pattern, value, expected", [
    ("*", "anything", True), ("listing:*", "listing:demo-01", True), ("listing:*", "repo:x", False),
    ("repo:jarvis", "repo:jarvis", True), ("repo:jarvis", "repo:jarvis2", False), ("x", None, False),
])
def test_pattern_matches(pattern, value, expected):
    assert pattern_matches(pattern, value) is expected


@pytest.mark.parametrize("parents, child, expected", [
    (["*"], "listing:*", True), (["listing:*"], "listing:demo-*", True), (["listing:*"], "listing:a", True),
    (["listing:demo-*"], "listing:*", False), (["listing:a"], "listing:*", False), (["listing:a"], "*", False),
    (["repo:jarvis"], "repo:jarvis", True), (["repo:jarvis"], "repo:jarvis*", False),
])
def test_pattern_covers(parents, child, expected):
    assert pattern_covers(parents, child) is expected


grant_patterns = st.lists(st.sampled_from(["*", "a*", "ab*", "abc", "ab", "b*", "bc", "a"]), min_size=1, max_size=4,
                          unique=True)
values = st.text(alphabet="abc", max_size=4)


@settings(max_examples=300)
@given(grant_patterns, st.sampled_from(["*", "a*", "ab*", "abc", "ab", "b*", "bc", "a"]), values)
def test_covered_patterns_never_match_more_than_their_parents(parents, child, value):
    """Soundness of attenuation: if child is covered, every value it matches is matched by a parent."""
    if pattern_covers(parents, child) and pattern_matches(child, value):
        assert any(pattern_matches(parent, value) for parent in parents)


capabilities = st.builds(
    lambda envs, scopes, resources, tools, amounts, depth: dict(
        environments=envs, scopes=scopes, resources=resources, tools=tools,
        approval_threshold_minor=amounts[0], per_action_minor=amounts[1], total_budget_minor=amounts[2],
        max_delegation_depth=depth),
    st.lists(st.sampled_from(["env:*", "env:research", "env:review", "*"]), min_size=1, max_size=3, unique=True),
    st.lists(st.sampled_from(["compute.simulate", "marketplace.read", "tool.invoke"]), min_size=1, max_size=3,
             unique=True),
    st.lists(st.sampled_from(["listing:*", "listing:demo-01", "listing:demo-*", "repo:jarvis", "*"]), min_size=1,
             max_size=3, unique=True),
    st.lists(st.sampled_from(["git.*", "git.status", "*"]), max_size=2, unique=True),
    st.lists(st.integers(min_value=0, max_value=200), min_size=3, max_size=3).map(sorted),
    st.integers(min_value=0, max_value=3),
)


@settings(max_examples=200, deadline=None)
@given(capabilities, capabilities)
def test_issuer_refuses_and_verifier_flags_exactly_the_non_attenuations(parent_cap, child_cap):
    parent_cap = {**parent_cap, "max_delegation_depth": 3}
    child_cap = {**child_cap, "max_delegation_depth": min(child_cap["max_delegation_depth"], 2)}
    root = issue_delegation(ROOT.signer, AGENT.did, parent_cap, valid_from=T, valid_until=T + 600)
    problems = attenuation_problems(Capability.model_validate(parent_cap), Capability.model_validate(child_cap))
    forged = forge(AGENT.signer, SUB.did, child_cap, valid_from=T, valid_until=T + 600, parent=root)
    result = verify([root, forged])
    assert result.authentic
    assert (not problems) == result.valid
    assert bool(problems) == any(code == "attenuation_violation" for _, code in codes(result))
    if problems:
        with pytest.raises(ValueError, match="not an attenuation"):
            issue_delegation(AGENT.signer, SUB.did, child_cap, valid_from=T, valid_until=T + 600, parent=root)
    else:
        issue_delegation(AGENT.signer, SUB.did, child_cap, valid_from=T, valid_until=T + 600, parent=root)


@settings(max_examples=100, deadline=None)
@given(capabilities, st.sampled_from(["env:research", "env:review", "env:other"]),
       st.sampled_from(["compute.simulate", "marketplace.read", "tool.invoke"]),
       st.sampled_from(["listing:demo-01", "listing:x", "repo:jarvis", "repo:other"]),
       st.sampled_from([None, "git.status", "git.push", "shell.exec"]), st.integers(min_value=0, max_value=250))
def test_a_request_allowed_by_a_child_is_allowed_by_its_parent(child_cap, environment, action, resource, tool, amount):
    """Monotonicity: attenuation can only remove permitted requests, never add them."""
    parent = Capability.model_validate(ROOT_CAP | {"environments": ["*"], "resources": ["*"], "tools": ["*"],
                                                   "per_action_minor": 150, "total_budget_minor": 200,
                                                   "approval_threshold_minor": 100})
    child = Capability.model_validate(child_cap)
    request = dict(environment=environment, action=action, resource=resource, tool=tool, amount_minor=amount)
    if not attenuation_problems(parent, child) and not capability_problems(child, **request):
        assert not capability_problems(parent, **request)


def test_capability_problems_reason_codes():
    capability = Capability.model_validate(SUB_CAP)
    assert capability_problems(capability, environment="env:research", action="compute.simulate",
                               resource="listing:demo-01", tool=None, amount_minor=30) == []
    reasons = [code for code, _ in capability_problems(capability, environment="env:review", action="tool.invoke",
                                                       resource="listing:other", tool=None, amount_minor=31)]
    assert reasons == ["environment_denied", "scope_denied", "resource_denied", "tool_required", "per_action_limit"]
    tool_cap = Capability.model_validate(AGENT_CAP)
    assert [c for c, _ in capability_problems(tool_cap, environment="env:research", action="tool.invoke",
                                              resource="repo:jarvis", tool="git.push", amount_minor=0)] == ["tool_denied"]



def test_deprecated_dex_order_sign_alias_matches_request_signature():
    # shortcut: alias accepted for 0.7 only; delete this test with the alias in 0.8.
    venue = dict(SUB_CAP, resources=["chain:31337:*"])
    old = Capability.model_validate(dict(venue, scopes=["dex.order.sign"]))
    new = Capability.model_validate(dict(venue, scopes=["dex.order.request_signature"]))
    for cap in (old, new):
        for action in ("dex.order.sign", "dex.order.request_signature"):
            assert capability_problems(cap, environment="env:research", action=action,
                                       resource="chain:31337:asset:RWA1", tool=None, amount_minor=0) == []
    assert attenuation_problems(old, new) == [] and attenuation_problems(new, old) == []
    other = Capability.model_validate(dict(venue, scopes=["dex.order.build"]))
    assert [c for c, _ in capability_problems(other, environment="env:research", action="dex.order.sign",
                                              resource="chain:31337:asset:RWA1", tool=None, amount_minor=0)] == ["scope_denied"]


# ---------------------------------------------------------------------- chain verification
def test_three_link_chain_verifies_back_to_the_root():
    chain = chain3()
    result = verify(chain)
    assert result.valid and result.authentic
    assert result.root == ROOT.did and result.leaf == STRANGER.did
    assert [link["issuer"] for link in result.links] == [ROOT.did, AGENT.did, SUB.did]
    assert result.capability.resources == ["listing:demo-01"]
    assert result.to_dict()["depth"] == 3


def test_untrusted_root_is_an_authorization_failure_but_authentic():
    result = verify(chain3(), roots=(STRANGER.did,))
    assert codes(result) == [(0, "untrusted_root")] and result.authentic and not result.valid
    assert verify(chain3(), roots=None).valid  # unpinned: any root (reported via result.root)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_tampering_with_any_link_breaks_its_signature(index):
    chain = copy.deepcopy(chain3())
    chain[index]["credentialSubject"]["capability"]["total_budget_minor"] += 1  # still schema-valid
    result = verify(chain)
    assert (index, "bad_signature") in codes(result) and not result.authentic


def test_replacing_a_parent_with_a_different_signed_credential_breaks_the_link():
    chain = chain3()
    other = issue_delegation(ROOT.signer, AGENT.did, ROOT_CAP, valid_from=T, valid_until=T + 7200)
    result = verify([other, chain[1], chain[2]])
    assert (1, "broken_link") in codes(result) and not result.authentic


def test_wrong_parent_digest_and_wrong_issuer_are_broken_links():
    d1 = chain3()[0]
    bad_digest = forge(AGENT.signer, SUB.did, AGENT_CAP, parent=d1, digest="0" * 64)
    assert (1, "broken_link") in codes(verify([d1, bad_digest]))
    impostor = forge(STRANGER.signer, SUB.did, AGENT_CAP, parent=d1)  # issuer is not d1's subject
    assert (1, "broken_link") in codes(verify([d1, impostor]))
    rooted_parent = forge(ROOT.signer, AGENT.did, ROOT_CAP, parent=d1)
    assert (0, "broken_link") in codes(verify([rooted_parent]))


def test_proof_by_another_key_than_the_issuer_is_rejected():
    d1 = chain3()[0]
    lying = copy.deepcopy(d1)
    lying["issuer"] = STRANGER.did
    assert (0, "bad_signature") in codes(verify([lying]))
    resigned = {k: v for k, v in d1.items() if k != "proof"}
    resigned = add_proof({**resigned, "issuer": ROOT.did}, STRANGER.signer, "capabilityDelegation", T)
    assert codes(verify([resigned])) == [(0, "bad_signature")]


def test_wrong_proof_purpose_is_malformed():
    d1 = chain3()[0]
    resigned = add_proof({k: v for k, v in d1.items() if k != "proof"}, ROOT.signer, "assertionMethod", T)
    assert codes(verify([resigned]))[0][1] == "malformed"


def test_depth_limits_are_enforced():
    d1 = issue_delegation(ROOT.signer, AGENT.did, {**ROOT_CAP, "max_delegation_depth": 0}, valid_from=T,
                          valid_until=T + 600)
    child = forge(AGENT.signer, SUB.did, {**AGENT_CAP, "max_delegation_depth": 0}, parent=d1, valid_until=T + 600)
    assert (1, "depth_exceeded") in codes(verify([d1, child]))
    d1 = issue_delegation(ROOT.signer, AGENT.did, ROOT_CAP, valid_from=T, valid_until=T + 600)
    same = forge(AGENT.signer, SUB.did, {**AGENT_CAP, "max_delegation_depth": 2}, parent=d1, valid_until=T + 600)
    assert (1, "depth_exceeded") in codes(verify([d1, same]))


def test_validity_window_cannot_widen_and_expiry_is_per_link():
    d1, d2 = chain2()
    longer = forge(AGENT.signer, SUB.did, AGENT_CAP | {"max_delegation_depth": 0}, parent=d1, valid_until=T + 9000)
    assert (1, "attenuation_violation") in codes(verify([d1, longer]))
    assert codes(verify([d1, d2], at=T + 3600)) == [(1, "expired")]
    assert codes(verify([d1, d2], at=T + 7200)) == [(0, "expired"), (1, "expired")]
    assert codes(verify([d1, d2], at=T - 3)) == [(0, "not_yet_valid"), (1, "not_yet_valid")]
    assert verify([d1, d2], at=T - 2).valid  # two seconds of clock skew, never more


def test_chain_shape_limits():
    assert codes(verify([])) == [(0, "malformed")]
    assert codes(verify("nope")) == [(0, "malformed")]
    assert codes(verify([chain3()[0]] * 11)) == [(0, "chain_too_long")]
    broken = copy.deepcopy(chain3())
    del broken[1]["credentialSubject"]["capability"]
    result = verify(broken)
    assert (1, "malformed") in codes(result) and (2, "broken_link") in codes(result)
    assert AUTHENTICITY_ERRORS.isdisjoint(AUTHORIZATION_ERRORS)


# ---------------------------------------------------------------------- revocation
def test_revocation_by_the_link_issuer_takes_effect_at_revoked_at():
    d1, d2 = chain2()
    record = issue_revocation(AGENT.signer, d2, revoked_at=T + 100)
    assert verify([d1, d2], at=T + 99, revocations=[record]).valid
    assert codes(verify([d1, d2], at=T + 100, revocations=[record])) == [(1, "revoked")]


def test_ancestors_and_the_subject_may_revoke_but_strangers_may_not():
    d1, d2 = chain2()
    for signer in (ROOT, AGENT, SUB):
        record = issue_revocation(signer.signer, d2, revoked_at=T)
        assert codes(verify([d1, d2], revocations=[record])) == [(1, "revoked")]
    stranger = issue_revocation(STRANGER.signer, d2, revoked_at=T)
    result = verify([d1, d2], revocations=[stranger])
    assert result.valid
    # The agent cannot revoke the root's delegation to itself? It can renounce it (it is the subject).
    assert codes(verify([d1, d2], revocations=[issue_revocation(AGENT.signer, d1, revoked_at=T)])) == [(0, "revoked")]
    assert verify([d1, d2], revocations=[issue_revocation(SUB.signer, d1, revoked_at=T)]).valid


def test_revoking_a_parent_invalidates_every_descendant_chain():
    chain = chain3()
    record = issue_revocation(ROOT.signer, chain[0], revoked_at=T)
    assert codes(verify(chain, revocations=[record])) == [(0, "revoked")]


def test_revocations_are_bound_to_the_exact_credential_and_must_verify():
    d1, d2 = chain2()
    record = issue_revocation(AGENT.signer, d2, revoked_at=T)
    other = issue_delegation(AGENT.signer, SUB.did, AGENT_CAP | {"max_delegation_depth": 0}, valid_from=T,
                             valid_until=T + 3600, parent=d1)
    assert verify([d1, other], revocations=[record]).valid  # different id and digest
    tampered = copy.deepcopy(record)
    tampered["revoked_at"] = format_time(T - 1)
    result = verify([d1, d2], revocations=[tampered, {"junk": True}])
    assert result.valid and result.ignored_revocations == 2
    with pytest.raises(ProofError):
        verify_revocation(tampered, Resolver())
    with pytest.raises(ProofError):
        verify_revocation({"type": "AutheoRevocation"}, Resolver())


# ---------------------------------------------------------------------- invocations
def invocation(chain, signer=SUB, **overrides):
    fields = dict(request_id="req:inv-1", environment="env:research", action="compute.simulate",
                  resource="listing:demo-01", amount_minor=10, created=T + 10)
    fields.update(overrides)
    return issue_invocation(signer.signer, chain, **fields)


def test_invocation_verifies_with_its_embedded_chain_offline():
    chain = chain2()
    result = verify_invocation(invocation(chain), resolver=Resolver(), at=T + 20, trusted_roots=[ROOT.did])
    assert result.chain.valid and result.invocation.invoker == SUB.did
    assert result.digest == document_digest(invocation(chain))


def test_invocation_failures():
    chain = chain2()
    with pytest.raises(ProofError) as error:
        verify_invocation(invocation(chain), resolver=Resolver(), at=T + 70)
    assert error.value.code == "expired"
    with pytest.raises(ProofError) as error:
        verify_invocation(invocation(chain), resolver=Resolver(), at=T + 7)
    assert error.value.code == "not_yet_valid"
    tampered = copy.deepcopy(invocation(chain))
    tampered["amount_minor"] = 11
    with pytest.raises(ProofError) as error:
        verify_invocation(tampered, resolver=Resolver(), at=T + 20)
    assert error.value.code == "bad_signature"
    with pytest.raises(ProofError) as error:
        verify_invocation({"type": "AutheoInvocation"}, resolver=Resolver(), at=T + 20)
    assert error.value.code == "malformed"
    lying = copy.deepcopy(invocation(chain, signer=AGENT))
    result = verify_invocation(lying, resolver=Resolver(), at=T + 20)
    assert (1, "invoker_mismatch") in codes(result.chain) and not result.chain.authentic
    with pytest.raises(ValueError):
        invocation(chain, ttl=301)
