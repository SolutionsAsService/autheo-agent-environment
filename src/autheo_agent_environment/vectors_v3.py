"""Generate tests/vectors/autheo-v3-pq-vectors.json (experimental hybrid / ML-DSA vectors).

ML-DSA signing is hedged (randomised, FIPS 204), so these vectors are VERIFY-ONLY:
keys are deterministic from fixed seeds, signatures are whatever was generated.
Run: python -m autheo_agent_environment.vectors_v3 [path]
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from .did import DidKey
from .pqc import PQ_SUITE, MldsaKey, add_hybrid_proofs, add_pq_proof, create_key_binding

T = 1_791_000_000
DOC = {"@context": ["https://www.w3.org/ns/credentials/v2"], "type": ["VerifiableCredential", "AutheoDelegation"],
       "issuer": "", "credentialSubject": {"scope": "compute.simulate", "resource": "listing:demo-01"}}


def build() -> dict:
    ed = DidKey.from_seed(bytes(range(32)))
    pq = MldsaKey.from_seed(bytes(range(32, 64)))
    doc = {**DOC, "issuer": ed.did}
    hybrid = add_hybrid_proofs(doc, ed.signer, pq.signer, "assertionMethod", T)
    tampered = copy.deepcopy(hybrid)
    tampered["credentialSubject"]["scope"] = "payments.send"
    stripped = {**hybrid, "proof": hybrid["proof"][0]}
    return {
        "version": "autheo-v3-pq-draft",
        "note": "verify-only; ML-DSA signatures are randomised. Experimental, not a stable contract.",
        "cryptosuite": PQ_SUITE,
        "keys": {"ed25519_did": ed.did, "mldsa44_did": pq.did, "mldsa44_seed_hex": pq.seed.hex(),
                 "mldsa44_public_hex": pq.public_raw.hex()},
        "cases": [
            {"name": "hybrid-valid", "policy": "hybrid", "bindings": {ed.did: pq.did}, "document": hybrid, "valid": True},
            {"name": "hybrid-tampered", "policy": "hybrid", "bindings": {ed.did: pq.did}, "document": tampered, "valid": False},
            {"name": "hybrid-stripped-pq", "policy": "hybrid", "bindings": {ed.did: pq.did}, "document": stripped, "valid": False},
            {"name": "hybrid-unbound", "policy": "hybrid", "bindings": {}, "document": hybrid, "valid": False},
            {"name": "pq-only-valid", "policy": "pq", "bindings": {}, "document": add_pq_proof(doc, pq.signer, "assertionMethod", T), "valid": True},
            {"name": "classical-only-under-pq", "policy": "pq", "bindings": {}, "document": stripped, "valid": False},
            {"name": "key-binding", "policy": "hybrid", "bindings": {ed.did: pq.did},
             "document": create_key_binding(ed.signer, pq.signer, T), "valid": True},
        ],
    }


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    path = Path(argv[0]) if argv else Path(__file__).resolve().parents[2] / "tests" / "vectors" / "autheo-v3-pq-vectors.json"
    path.write_text(json.dumps(build(), indent=2) + "\n")
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
