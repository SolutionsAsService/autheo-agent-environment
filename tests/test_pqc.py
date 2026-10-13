"""Hybrid Ed25519 + ML-DSA-44 proofs and key bindings (experimental v3 draft)."""

import copy

import pytest

from autheo_agent_environment.data_integrity import ProofError, verify_proof
from autheo_agent_environment.did import DidKey, Resolver
from autheo_agent_environment.pqc import (
    PQ_SUITE,
    MldsaKey,
    add_hybrid_proofs,
    add_pq_proof,
    create_key_binding,
    is_mldsa_did,
    mldsa_did_document,
    mldsa_public_from_did,
    verify_key_binding,
    verify_proofs,
)

T = 1_791_000_000
DOC = {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"], "issuer": "x",
       "credentialSubject": {"id": "did:example:agent", "scope": "compute.simulate"}}


@pytest.fixture(scope="module")
def keys():
    return DidKey.from_seed(bytes(32)), MldsaKey.from_seed(bytes(range(32)))


def test_mldsa_did_key_round_trip(keys):
    _, pq = keys
    assert pq.did.startswith("did:key:z") and is_mldsa_did(pq.did)
    assert mldsa_public_from_did(pq.did) == pq.public_raw
    assert MldsaKey.from_seed(pq.seed).did == pq.did, "deterministic from seed"
    doc = mldsa_did_document(pq.did)
    assert doc["verificationMethod"][0]["id"] == pq.verification_method
    assert not is_mldsa_did(keys[0].did)


def test_hybrid_proof_set_verifies_and_stays_classically_compatible(keys):
    ed, pq = keys
    secured = add_hybrid_proofs(DOC, ed.signer, pq.signer, "assertionMethod", T)
    assert [p["cryptosuite"] for p in secured["proof"]] == ["eddsa-jcs-2022", PQ_SUITE]
    result = verify_proofs(secured, "assertionMethod", policy="hybrid", bindings={ed.did: pq.did})
    assert result.classical.controller == ed.did and result.post_quantum.controller == pq.did
    classical_only = {**secured, "proof": secured["proof"][0]}
    verify_proof(classical_only, Resolver(), "assertionMethod")  # unchanged v2 verifier


def test_hybrid_policy_rejects_stripping_and_unbound_keys(keys):
    ed, pq = keys
    secured = add_hybrid_proofs(DOC, ed.signer, pq.signer, "assertionMethod", T)
    stripped = {**secured, "proof": secured["proof"][0]}
    with pytest.raises(ProofError, match="hybrid_required"):
        verify_proofs(stripped, "assertionMethod", policy="hybrid", bindings={ed.did: pq.did})
    with pytest.raises(ProofError, match="unbound_keys"):
        verify_proofs(secured, "assertionMethod", policy="hybrid", bindings={})
    other = MldsaKey.generate()
    swapped = add_hybrid_proofs(DOC, ed.signer, other.signer, "assertionMethod", T)
    with pytest.raises(ProofError, match="unbound_keys"):
        verify_proofs(swapped, "assertionMethod", policy="hybrid", bindings={ed.did: pq.did})
    assert verify_proofs(stripped, "assertionMethod", policy="classical").classical


def test_tampering_breaks_pq_proof(keys):
    ed, pq = keys
    secured = add_pq_proof(DOC, pq.signer, "assertionMethod", T)
    assert verify_proofs(secured, "assertionMethod", policy="pq").post_quantum
    tampered = copy.deepcopy(secured)
    tampered["credentialSubject"]["scope"] = "payments.send"
    with pytest.raises(ProofError, match="bad_signature"):
        verify_proofs(tampered, "assertionMethod", policy="pq")
    wrong_purpose = add_pq_proof(DOC, pq.signer, "authentication", T)
    with pytest.raises(ProofError, match="purpose"):
        verify_proofs(wrong_purpose, "assertionMethod", policy="pq")
    hybrid = add_hybrid_proofs(DOC, ed.signer, pq.signer, "assertionMethod", T)
    with pytest.raises(ProofError, match="pq_required"):
        verify_proofs({**hybrid, "proof": hybrid["proof"][0]}, "assertionMethod", policy="pq")


def test_invalid_extra_proof_fails_the_set(keys):
    ed, pq = keys
    secured = add_hybrid_proofs(DOC, ed.signer, pq.signer, "assertionMethod", T)
    bad = copy.deepcopy(secured)
    bad["proof"][1]["proofValue"] = bad["proof"][0]["proofValue"]
    with pytest.raises(ProofError):
        verify_proofs(bad, "assertionMethod", policy="classical")


def test_key_binding_requires_both_keys(keys):
    ed, pq = keys
    binding = create_key_binding(ed.signer, pq.signer, T, valid_until=T + 86400)
    assert verify_key_binding(binding, now=T + 1) == (ed.did, pq.did)
    with pytest.raises(ProofError, match="expired"):
        verify_key_binding(binding, now=T + 86401)
    forged = copy.deepcopy(binding)
    forged["credentialSubject"]["alsoKnownAs"] = [MldsaKey.generate().did]
    with pytest.raises(ProofError):
        verify_key_binding(forged)
