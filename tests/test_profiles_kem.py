"""Tunable PQ strength (profiles) and hybrid X25519+ML-KEM sealing."""

import pytest

from autheo_agent_environment.data_integrity import ProofError
from autheo_agent_environment.did import DidKey
from autheo_agent_environment.kem import HybridKemKey, HybridKemPublic, open_sealed, seal
from autheo_agent_environment.pqc import (
    MLDSA,
    MldsaKey,
    add_hybrid_proofs,
    add_pq_proof,
    mldsa_key_info,
    verify_proofs,
)
from autheo_agent_environment.profiles import PROFILES, custom_profile, get_profile

T = 1_791_000_000
DOC = {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential"], "credentialSubject": {"scope": "x"}}


@pytest.mark.parametrize("level", [44, 65, 87])
def test_every_level_signs_and_verifies(level):
    ed, pq = DidKey.from_seed(bytes(32)), MldsaKey.from_seed(bytes(range(32)), level)
    p, raw = mldsa_key_info(pq.did)
    assert p.level == level and len(raw) == MLDSA[level].public_bytes
    secured = add_hybrid_proofs(DOC, ed.signer, pq.signer, "assertionMethod", T)
    assert secured["proof"][1]["cryptosuite"] == f"mldsa{level}-jcs-2024"
    r = verify_proofs(secured, "assertionMethod", policy="hybrid", bindings={ed.did: pq.did}, min_category=MLDSA[level].nist_category)
    assert r.post_quantum.nist_category == MLDSA[level].nist_category


def test_min_category_rejects_weaker_signatures():
    pq44 = MldsaKey.generate(44)
    secured = add_pq_proof(DOC, pq44.signer, "assertionMethod", T)
    verify_proofs(secured, "assertionMethod", policy="pq", min_category=2)
    with pytest.raises(ProofError, match="pq_level_too_low"):
        verify_proofs(secured, "assertionMethod", policy="pq", min_category=3)


def test_suite_level_mismatch_rejected():
    pq65 = MldsaKey.generate(65)
    secured = add_pq_proof(DOC, pq65.signer, "assertionMethod", T)
    secured["proof"]["cryptosuite"] = "mldsa44-jcs-2024"
    with pytest.raises(ProofError):
        verify_proofs(secured, "assertionMethod", policy="pq")


def test_profiles(monkeypatch):
    assert get_profile().name == "balanced" and get_profile().mldsa_level == 65
    monkeypatch.setenv("AUTHEO_SECURITY_PROFILE", "max")
    assert get_profile().mlkem_level == 1024 and get_profile().min_category == 5
    with pytest.raises(ValueError):
        get_profile("ultra")
    assert [PROFILES[n].signature_bytes for n in ("compact", "balanced", "max")] == [2420, 3309, 4627]
    with pytest.raises(ValueError):
        custom_profile("bad", mldsa_level=44, min_category=5)
    assert custom_profile("edge", mldsa_level=65, mlkem_level=1024).min_category == 3


@pytest.mark.parametrize("level", [768, 1024])
def test_hybrid_kem_round_trip_and_tamper(level):
    k = HybridKemKey.generate(level)
    pub = HybridKemPublic.decode(k.public.encode(), level)
    env = seal(pub, b"checkpoint: agent-7 state", aad=b"handoff-42")
    assert env["alg"] == f"X25519-MLKEM{level}-A256GCM"
    assert open_sealed(k, env, aad=b"handoff-42") == b"checkpoint: agent-7 state"
    with pytest.raises(ValueError):
        open_sealed(k, env, aad=b"other")
    with pytest.raises(ValueError):
        open_sealed(HybridKemKey.generate(level), env, aad=b"handoff-42")
    bad = dict(env, data=env["data"][:-4] + "AAAA")
    with pytest.raises(ValueError):
        open_sealed(k, bad, aad=b"handoff-42")
