"""Deterministic v2 cross-language test vectors (tests/vectors/autheo-v2-vectors.json).

Everything is reproducible byte-for-byte: Ed25519 signatures are deterministic,
seeds are PUBLIC TEST VALUES (sha256("autheo-test-vector-seed:v2:" + label)), and
ids and timestamps are fixed. Expected results come from the Python reference
implementation; interop/js/verify-v2-vectors.mjs must agree with every case.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from .canonical import ZERO_HASH
from .data_integrity import add_proof, format_time, hash_data
from .delegation import (
    CLOCK_SKEW_SECONDS,
    document_digest,
    issue_delegation,
    issue_invocation,
    issue_revocation,
    verify_chain,
    verify_invocation,
)
from .did import DidKey, Resolver, did_key_document, did_web_url
from .jcs import canonicalize
from .models_v2 import VC_CONTEXT, Capability
from .multibase import b58encode, varint_encode
from .policy import DEFAULT_POLICY
from .verifier import v2_chain_hash, verify_bundle, verify_receipts

VECTOR_VERSION = "autheo-test-vectors/v2"
NOW = 1_790_000_000  # 2026-09-21T14:13:20Z
ENVIRONMENT = "env:research"
W3C_SECRET = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
W3C_CREDENTIAL = {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/examples/v2"],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {"id": "did:example:abcdefgh", "alumniOf": "The School of Examples"},
}
ROOT_CAP = {"environments": ["env:*"], "scopes": ["compute.simulate", "marketplace.read", "tool.invoke"],
            "resources": ["listing:*", "repo:jarvis"], "tools": ["git.*"], "per_action_minor": 80,
            "total_budget_minor": 100, "approval_threshold_minor": 50, "max_delegation_depth": 2}
AGENT_CAP = {"environments": ["env:research"], "scopes": ["compute.simulate", "tool.invoke"],
             "resources": ["listing:demo-*", "repo:jarvis"], "tools": ["git.status"], "per_action_minor": 60,
             "total_budget_minor": 80, "approval_threshold_minor": 40, "max_delegation_depth": 1}
SUB_CAP = {"environments": ["env:research"], "scopes": ["compute.simulate"], "resources": ["listing:demo-01"],
           "per_action_minor": 30, "total_budget_minor": 50, "approval_threshold_minor": 20,
           "max_delegation_depth": 0}


def _uuid(n: int) -> str:
    return f"urn:uuid:00000000-0000-4000-8000-{n:012d}"


def _key(label: str) -> DidKey:
    return DidKey.from_seed(hashlib.sha256(f"autheo-test-vector-seed:v2:{label}".encode()).digest())


def _forge(signer, subject, capability, *, valid_from, valid_until, parent=None, digest=None, number=299):
    body = {"id": subject, "schema_version": "autheo.delegation/v2",
            "capability": Capability.model_validate(capability).model_dump(mode="json")}
    if parent is not None:
        body["parent"] = {"id": parent["id"], "digest": digest or document_digest(parent)}
    document = {"@context": [VC_CONTEXT], "type": ["VerifiableCredential", "AutheoDelegation"], "id": _uuid(number),
                "issuer": signer.did, "validFrom": format_time(valid_from), "validUntil": format_time(valid_until),
                "credentialSubject": body}
    return add_proof(document, signer, "capabilityDelegation", valid_from)


def _receipt(env_key: DidKey, previous: str, sequence: int, body: dict, number: int) -> dict:
    recorded_at = NOW + 30 + sequence
    document = {"type": "AutheoReceipt", "schema_version": "autheo.receipt/v2", "id": _uuid(number),
                "issuer": env_key.did, "environment": ENVIRONMENT, "sequence": sequence, "previous_hash": previous,
                "recorded_at": recorded_at, **{k: v for k, v in body.items() if v is not None},
                "executed": False, "simulation_only": True}
    return add_proof(document, env_key.signer, "assertionMethod", recorded_at)


def _chain_body(invocation: dict) -> dict:
    result = verify_invocation(invocation, resolver=Resolver(), at=NOW + 31)
    return {"document_digest": result.digest, "request_id": invocation["id"], "invoker": invocation["invoker"],
            "root": result.chain.root,
            "chain": [{k: link[k] for k in ("id", "digest", "issuer", "subject")} for link in result.chain.links],
            "action": invocation["action"], "resource": invocation["resource"], "tool": invocation.get("tool"),
            "amount_minor": invocation["amount_minor"], "policy_id": DEFAULT_POLICY.policy_id,
            "policy_digest": DEFAULT_POLICY.digest}


def _errors(result) -> list:
    pairs = []
    for error in result.errors:
        if [error.index, error.code] not in pairs:
            pairs.append([error.index, error.code])
    return pairs


def primitives() -> dict:
    jcs_inputs = [
        ("rfc8785_sorting", '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With '
                            'Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control",'
                            '"\\u00f6":"Latin Small Letter O With Diaeresis"}'),
        ("rfc8785_strings", '{"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
                            '"literals":[null,true,false]}'),
        ("nested_and_controls", '{"b":[1,{"z":-5,"a":"\\u001f\\u007f\\u2028"}],"a":{}}'),
        ("empty_values", '{"":"","list":[],"obj":{}}'),
    ]
    jcs = []
    for name, text in jcs_inputs:
        value = json.loads(text)
        jcs.append({"name": name, "json": text, "canonical": canonicalize(value).decode("utf-8"),
                    "sha256": hashlib.sha256(canonicalize(value)).hexdigest()})
    for name, text in [("float_rejected", '{"a":1.5}'), ("unsafe_integer_rejected", '{"a":9007199254740992}'),
                       ("lone_surrogate_rejected", '{"a":"\\ud800"}')]:
        jcs.append({"name": name, "json": text, "error": True})
    base58 = [{"hex": data.hex(), "encoded": b58encode(data)} for data in
              [b"Hello World!", b"The quick brown fox jumps over the lazy dog.", bytes.fromhex("0000287fb4cd"),
               b"", b"\0\0", bytes(range(32))]]
    varints = [{"value": v, "hex": varint_encode(v).hex()} for v in (0, 1, 127, 128, 0xED, 0xEC, 0x1300, 16384)]
    w3c = DidKey.from_secret_multibase(W3C_SECRET)
    spec_did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    did_keys = [
        {"name": "w3c_vc_di_eddsa_keypair", "secret_multibase": W3C_SECRET, "seed_hex": w3c.seed().hex(),
         "public_hex": w3c.public_raw.hex(), "did": w3c.did},
        {"name": "did_key_spec_x25519_example", "did": spec_did,
         "public_hex": _public_hex(spec_did),
         "x25519_multibase": "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
         "document": did_key_document(spec_did)},
    ]
    for label in ("root", "agent"):
        key = _key(label)
        did_keys.append({"name": f"test_seed_{label}", "seed_hex": key.seed().hex(), "public_hex": key.public_raw.hex(),
                         "did": key.did})
    invalid_did_keys = ["did:key:z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
                        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
                        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do", "did:key:mAAAA", "did:web:x.example"]
    did_web = [{"did": d, "url": did_web_url(d)} for d in ("did:web:w3c-ccg.github.io",
                                                           "did:web:w3c-ccg.github.io:user:alice",
                                                           "did:web:example.com%3A3000:user:alice")]
    proof_options = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022", "created": "2023-02-24T23:36:38Z",
                     "verificationMethod": w3c.verification_method, "proofPurpose": "assertionMethod",
                     "@context": W3C_CREDENTIAL["@context"]}
    signed = add_proof(W3C_CREDENTIAL, w3c.signer, "assertionMethod", 1_677_281_798)
    w3c_example = {"source": "W3C Data Integrity EdDSA Cryptosuites v1.0, Appendix B.3", "document": W3C_CREDENTIAL,
                   "secret_multibase": W3C_SECRET, "proof_options": proof_options,
                   "canonical_document": canonicalize(W3C_CREDENTIAL).decode(),
                   "canonical_proof_options": canonicalize(proof_options).decode(),
                   "hash_data_hex": hash_data(W3C_CREDENTIAL, proof_options).hex(),
                   "proof_value": signed["proof"]["proofValue"], "signed": signed}
    return {"jcs": jcs, "base58": base58, "varint": varints, "did_key": did_keys,
            "invalid_did_key": invalid_did_keys, "did_web": did_web, "w3c_eddsa_jcs_2022": w3c_example}


def _public_hex(did: str) -> str:
    from .did import public_from_did_key

    return public_from_did_key(did).hex()


def build() -> dict:  # noqa: PLR0915 - one linear fixture script
    root, agent, sub, helper, stranger, env = (_key(n) for n in ("root", "agent", "subagent", "helper", "stranger",
                                                                 "environment"))
    keys = {name: {"did": key.did, "TEST_ONLY_seed_hex": key.seed().hex()} for name, key in
            [("root", root), ("agent", agent), ("subagent", sub), ("helper", helper), ("stranger", stranger),
             ("environment", env)]}
    d1 = issue_delegation(root.signer, agent.did, ROOT_CAP, valid_from=NOW, valid_until=NOW + 7200,
                          delegation_id=_uuid(201))
    d2 = issue_delegation(agent.signer, sub.did, AGENT_CAP, valid_from=NOW, valid_until=NOW + 3600, parent=d1,
                          delegation_id=_uuid(202))
    d3 = issue_delegation(sub.signer, helper.did, SUB_CAP, valid_from=NOW, valid_until=NOW + 1800, parent=d2,
                          delegation_id=_uuid(203))
    revoke_d2 = issue_revocation(agent.signer, d2, revoked_at=NOW + 100, revocation_id=_uuid(211))
    root_revokes_d2 = issue_revocation(root.signer, d2, revoked_at=NOW + 100, revocation_id=_uuid(212))
    stranger_revokes_d2 = issue_revocation(stranger.signer, d2, revoked_at=NOW + 100, revocation_id=_uuid(213))
    tampered_revocation = copy.deepcopy(revoke_d2)
    tampered_revocation["revoked_at"] = format_time(NOW + 50)

    tampered_d2 = copy.deepcopy(d2)
    tampered_d2["credentialSubject"]["capability"]["total_budget_minor"] += 1
    widened = _forge(agent.signer, sub.did, {**AGENT_CAP, "scopes": ["compute.simulate", "model.invoke"]},
                     valid_from=NOW, valid_until=NOW + 3600, parent=d1, number=221)
    longer = _forge(agent.signer, sub.did, AGENT_CAP, valid_from=NOW, valid_until=NOW + 9000, parent=d1, number=222)
    bad_digest = _forge(agent.signer, sub.did, AGENT_CAP, valid_from=NOW, valid_until=NOW + 3600, parent=d1,
                        digest="0" * 64, number=223)
    wrong_issuer = _forge(stranger.signer, sub.did, AGENT_CAP, valid_from=NOW, valid_until=NOW + 3600, parent=d1,
                          number=224)
    too_deep = _forge(helper.signer, stranger.did, SUB_CAP, valid_from=NOW, valid_until=NOW + 1800, parent=d3,
                      number=225)
    wrong_purpose = add_proof({k: v for k, v in d1.items() if k != "proof"}, root.signer, "assertionMethod", NOW)

    def case(name, chain, at=NOW + 60, roots=(root.did,), revocations=()):
        roots = None if roots is None else list(roots)
        result = verify_chain(chain, resolver=Resolver(), at=at, trusted_roots=roots, revocations=list(revocations),
                              skew=CLOCK_SKEW_SECONDS)
        return {"name": name, "chain": chain, "at": at, "trusted_roots": roots, "revocations": list(revocations),
                "expect_valid": result.valid, "expect_authentic": result.authentic, "expect_errors": _errors(result),
                "expect_root": result.root, "expect_leaf": result.leaf}

    chain_cases = [
        case("valid_two_links", [d1, d2]),
        case("valid_three_links", [d1, d2, d3]),
        case("valid_unpinned_root", [d1, d2], roots=None),
        case("untrusted_root", [d1, d2], roots=(stranger.did,)),
        case("tampered_capability", [d1, tampered_d2, d3]),
        case("forged_widening", [d1, widened]),
        case("validity_widened", [d1, longer]),
        case("broken_parent_digest", [d1, bad_digest]),
        case("issuer_is_not_parent_subject", [d1, wrong_issuer]),
        case("depth_exceeded", [d1, d2, d3, too_deep]),
        case("wrong_proof_purpose", [wrong_purpose, d2]),
        case("expired_link", [d1, d2], at=NOW + 3600),
        case("all_expired", [d1, d2], at=NOW + 7200),
        case("not_yet_valid", [d1, d2], at=NOW - 3),
        case("within_clock_skew", [d1, d2], at=NOW - 2),
        case("revoked_by_issuer", [d1, d2, d3], at=NOW + 100, revocations=[revoke_d2]),
        case("revoked_by_root", [d1, d2], at=NOW + 100, revocations=[root_revokes_d2]),
        case("revocation_not_yet_effective", [d1, d2], at=NOW + 99, revocations=[revoke_d2]),
        case("stranger_revocation_ignored", [d1, d2], at=NOW + 100, revocations=[stranger_revokes_d2]),
        case("tampered_revocation_ignored", [d1, d2], at=NOW + 100, revocations=[tampered_revocation]),
        case("chain_too_long", [d1] * 11),
        case("empty_chain", []),
    ]

    invocation = issue_invocation(sub.signer, [d1, d2], request_id="req:v2-allow", environment=ENVIRONMENT,
                                  action="compute.simulate", resource="listing:demo-01", amount_minor=20,
                                  created=NOW + 10)
    blocked_invocation = issue_invocation(sub.signer, [d1, d2], request_id="req:v2-block", environment=ENVIRONMENT,
                                          action="marketplace.read", resource="listing:demo-01", amount_minor=0,
                                          created=NOW + 11)
    tampered_invocation = copy.deepcopy(invocation)
    tampered_invocation["amount_minor"] = 21
    agent_invocation = issue_invocation(agent.signer, [d1, d2], request_id="req:v2-wrong-invoker",
                                        environment=ENVIRONMENT, action="compute.simulate",
                                        resource="listing:demo-01", amount_minor=1, created=NOW + 10)

    def invocation_case(name, document, at):
        try:
            result = verify_invocation(document, resolver=Resolver(), at=at, trusted_roots=[root.did])
        except ValueError as error:
            return {"name": name, "invocation": document, "at": at, "expect_error": getattr(error, "code", "error")}
        return {"name": name, "invocation": document, "at": at, "expect_error": None,
                "expect_digest": result.digest, "expect_chain_valid": result.chain.valid,
                "expect_chain_errors": _errors(result.chain)}

    invocation_cases = [
        invocation_case("valid", invocation, NOW + 20),
        invocation_case("expired", invocation, NOW + 70),
        invocation_case("not_yet_valid", invocation, NOW + 7),
        invocation_case("tampered", tampered_invocation, NOW + 20),
        invocation_case("invoker_is_not_leaf_subject", agent_invocation, NOW + 20),
    ]

    receipts, previous = [], ZERO_HASH
    plan = [
        ({"kind": "decision", "decision": "allow", "reasons": ["within_demo_policy"], **_chain_body(invocation)}, 301),
        ({"kind": "decision", "decision": "block", "reasons": ["scope_denied"],
          **_chain_body(blocked_invocation)}, 302),
        ({"kind": "revocation", "decision": "recorded", "reasons": ["revocation_recorded", "revocation_reason:revoked"],
          "document_digest": document_digest(revoke_d2), "reference": revoke_d2["id"]}, 303),
    ]
    for sequence, (body, number) in enumerate(plan, 1):
        receipt = _receipt(env, previous, sequence, body, number)
        receipts.append(receipt)
        previous = v2_chain_hash(previous, receipt)
    ledger = {"schema_version": "autheo.ledger-export/v2", "environment": ENVIRONMENT, "issuer": env.did,
              "head": previous, "receipts": receipts}
    tampered_ledger = copy.deepcopy(ledger)
    tampered_ledger["receipts"][1]["reasons"] = ["within_demo_policy"]
    tampered_report = verify_receipts(tampered_ledger["receipts"], resolver=Resolver(), issuer=env.did,
                                      environment=ENVIRONMENT)

    bundle = {"schema_version": "autheo.bundle/v2", "receipt": receipts[0], "invocation": invocation,
              "revocations": []}
    block_bundle = {"schema_version": "autheo.bundle/v2", "receipt": receipts[1], "invocation": blocked_invocation,
                    "revocations": []}
    edited = copy.deepcopy(bundle)
    edited["receipt"]["decision"] = "block"
    swapped = {**bundle, "invocation": blocked_invocation}
    early_revocation = issue_revocation(root.signer, d1, revoked_at=NOW + 20, revocation_id=_uuid(214))

    def bundle_case(name, document, roots=(root.did,), environment_did=None, revocations=()):
        roots = None if roots is None else list(roots)
        report = verify_bundle(document, resolver=Resolver(), trusted_roots=roots, environment_did=environment_did,
                               extra_revocations=list(revocations))
        return {"name": name, "bundle": document, "trusted_roots": roots, "environment_did": environment_did,
                "revocations": list(revocations), "expect_valid": report["valid"],
                "expect_problems": report["problems"], "expect_verdict": report.get("verdict"),
                "expect_authorized": report.get("authorized_by_chain")}

    bundle_cases = [
        bundle_case("allow_verified", bundle, environment_did=env.did),
        bundle_case("block_verified", block_bundle, environment_did=env.did),
        bundle_case("unpinned_root", bundle, roots=None),
        bundle_case("wrong_environment_did", bundle, environment_did=root.did),
        bundle_case("tampered_receipt", edited),
        bundle_case("swapped_invocation", swapped),
        bundle_case("untrusted_root", bundle, roots=(stranger.did,)),
        bundle_case("revoked_before_decision", bundle, revocations=[early_revocation]),
    ]
    return {
        "version": VECTOR_VERSION,
        "spec": "docs/SPEC-DID.md",
        "warning": "TEST_ONLY seeds are public; never use them for real keys.",
        "now": NOW,
        "clock_skew_seconds": CLOCK_SKEW_SECONDS,
        "primitives": primitives(),
        "keys": keys,
        "delegations": {"root_to_agent": d1, "agent_to_subagent": d2, "subagent_to_helper": d3},
        "digests": {"root_to_agent": document_digest(d1), "agent_to_subagent": document_digest(d2)},
        "revocations": {"agent_revokes_agent_to_subagent": revoke_d2},
        "chain_cases": chain_cases,
        "invocation_cases": invocation_cases,
        "bundle_cases": bundle_cases,
        "ledger": ledger,
        "tampered_ledger": {"export": tampered_ledger,
                            "expect_first_invalid_sequence": tampered_report["first_invalid_sequence"]},
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write(path: Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(render(), encoding="utf-8")
