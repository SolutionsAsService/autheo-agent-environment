"""Post-quantum and hybrid proofs (Autheo v3 draft, experimental): ML-DSA-44 did:key,
the `mldsa44-jcs-2024` Data Integrity cryptosuite, hybrid proof sets and
cross-signed key bindings.

Why: Ed25519 (eddsa-jcs-2022, v2) is broken by a cryptographically relevant
quantum computer. Signed delegations and receipts are long-lived evidence, so
they need a migration path *before* that happens ("harvest now, forge later").
This module adds that path without changing v2 bytes:

* **ML-DSA-44 keys (FIPS 204)** via `cryptography` (OpenSSL 3.5). A did:key for
  ML-DSA-44 is base58btc multibase of multicodec 0x1210 (`mldsa-44-pub`,
  multicodec table, draft status) + the 1312-byte public key.
* **Cryptosuite `mldsa44-jcs-2024`** (W3C CCG *Quantum-Safe Cryptosuites* draft):
  same transformation and hashing as eddsa-jcs-2022 (JCS + SHA-256 of proof
  config || SHA-256 of document); proofValue = "z" + base58btc(ML-DSA-44 sig).
* **Hybrid proof sets**: a document carries `proof: [eddsa, mldsa]`. Each proof
  is created over the unsecured document independently (W3C Data Integrity
  proof sets), so classical verifiers still work and stripping either proof is
  detected by a hybrid verifier.
* **Key binding**: `AutheoKeyBinding` credentials state that an Ed25519 did:key
  and an ML-DSA did:key belong to one principal; the binding carries BOTH
  proofs, so neither key can claim the other alone.
* **Verifier policy**: `classical` (Ed25519 suffices), `hybrid` (both proofs,
  from bound keys, must verify), `pq` (ML-DSA proof required).

Status: experimental. Not yet wired into delegation chains, receipts or the JS
browser verifier (browsers have no ML-DSA in WebCrypto yet); see
docs/PQC-ROADMAP.md. ML-DSA signing is hedged (randomised) per FIPS 204, so PQ
vectors are verify-only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey, MLDSA44PublicKey

from .data_integrity import CRYPTOSUITE as EDDSA_SUITE
from .data_integrity import PROOF_TYPE, ProofError, format_time, hash_data, parse_time
from .did import DidError, DidSigner, Resolver
from .multibase import multibase_decode, multibase_encode, multicodec_unwrap, multicodec_wrap

MLDSA44_PUB = 0x1210
MLDSA44_PUBLIC_BYTES = 1312
MLDSA44_SIGNATURE_BYTES = 2420
PQ_SUITE = "mldsa44-jcs-2024"
SUITES = (EDDSA_SUITE, PQ_SUITE)
POLICIES = ("classical", "hybrid", "pq")
KEY_BINDING_TYPE = "AutheoKeyBinding"
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
PROOF_MEMBERS = {"type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue", "@context"}
_MLDSA_DID = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]{1700,1900}$")


# ---------------------------------------------------------------------- ML-DSA did:key
def mldsa_did_from_public(raw: bytes) -> str:
    if len(raw) != MLDSA44_PUBLIC_BYTES:
        raise DidError("invalidPublicKeyLength", "ML-DSA-44 public keys are 1312 bytes")
    return "did:key:" + multibase_encode(multicodec_wrap(MLDSA44_PUB, raw))


def mldsa_public_from_did(did: str) -> bytes:
    if not isinstance(did, str) or not _MLDSA_DID.match(did):
        raise DidError("invalidDid", "not an ML-DSA-44 did:key")
    try:
        code, raw = multicodec_unwrap(multibase_decode(did.split(":")[2]))
    except ValueError as error:
        raise DidError("invalidDid", str(error)) from error
    if code != MLDSA44_PUB or len(raw) != MLDSA44_PUBLIC_BYTES:
        raise DidError("unsupportedPublicKeyType", "expected mldsa-44-pub (0x1210)")
    if mldsa_did_from_public(raw) != did:
        raise DidError("invalidDid", "non-canonical did:key encoding")
    return raw


def is_mldsa_did(did: str) -> bool:
    try:
        mldsa_public_from_did(did)
        return True
    except DidError:
        return False


def mldsa_did_document(did: str) -> dict:
    mldsa_public_from_did(did)
    fingerprint = did.split(":")[2]
    method = {"id": f"{did}#{fingerprint[:48]}", "type": "Multikey", "controller": did, "publicKeyMultibase": fingerprint}
    rel = ("authentication", "assertionMethod", "capabilityDelegation", "capabilityInvocation")
    return {"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did, "verificationMethod": [method], **{r: [method["id"]] for r in rel}}


@dataclass(frozen=True)
class MldsaSigner:
    """ML-DSA-44 private key plus the did:key and verification method it signs for."""

    did: str
    verification_method: str
    key: MLDSA44PrivateKey

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)


@dataclass(frozen=True)
class MldsaKey:
    """An ML-DSA-44 key pair; like Ed25519 did:key, creating one needs nobody's permission."""

    key: MLDSA44PrivateKey

    @classmethod
    def generate(cls) -> MldsaKey:
        return cls(MLDSA44PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> MldsaKey:
        if len(seed) != 32:
            raise ValueError("ML-DSA-44 seeds are 32 bytes")
        return cls(MLDSA44PrivateKey.from_seed_bytes(seed))

    @property
    def public_raw(self) -> bytes:
        from cryptography.hazmat.primitives import serialization as s

        return self.key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)

    @property
    def seed(self) -> bytes:
        return self.key.private_bytes_raw()

    @property
    def did(self) -> str:
        return mldsa_did_from_public(self.public_raw)

    @property
    def verification_method(self) -> str:
        return f"{self.did}#{self.did.split(':')[2][:48]}"

    @property
    def signer(self) -> MldsaSigner:
        return MldsaSigner(self.did, self.verification_method, self.key)


# ---------------------------------------------------------------------- proofs
def _proof_options(signer, suite: str, purpose: str, created: int, document: dict) -> dict:
    options = {"type": PROOF_TYPE, "cryptosuite": suite, "created": format_time(created),
               "verificationMethod": signer.verification_method, "proofPurpose": purpose}
    if "@context" in document:
        options["@context"] = document["@context"]
    return options


def _make_proof(document: dict, signer, purpose: str, created: int) -> dict:
    suite = PQ_SUITE if isinstance(signer, MldsaSigner) else EDDSA_SUITE
    options = _proof_options(signer, suite, purpose, created, document)
    return {**options, "proofValue": multibase_encode(signer.sign(hash_data(document, options)))}


def add_hybrid_proofs(document: dict, classical: DidSigner, pq: MldsaSigner, purpose: str, created: int) -> dict:
    """Attach a proof set [eddsa-jcs-2022, mldsa44-jcs-2024] over the same unsecured document."""
    if not isinstance(document, dict) or "proof" in document:
        raise ValueError("document must be a JSON object without a proof")
    return {**document, "proof": [_make_proof(document, classical, purpose, created),
                                  _make_proof(document, pq, purpose, created)]}


def add_pq_proof(document: dict, pq: MldsaSigner, purpose: str, created: int) -> dict:
    if not isinstance(document, dict) or "proof" in document:
        raise ValueError("document must be a JSON object without a proof")
    return {**document, "proof": _make_proof(document, pq, purpose, created)}


@dataclass(frozen=True)
class SuiteResult:
    cryptosuite: str
    controller: str
    verification_method: str
    created: int


def _verify_one(unsecured: dict, proof: dict, resolver: Resolver | None, purpose: str) -> SuiteResult:
    if not isinstance(proof, dict) or set(proof) - PROOF_MEMBERS:
        raise ProofError("bad_proof", "malformed proof object")
    suite = proof.get("cryptosuite")
    if proof.get("type") != PROOF_TYPE or suite not in SUITES:
        raise ProofError("bad_proof", f"unsupported cryptosuite {suite!r}")
    if proof.get("proofPurpose") != purpose:
        raise ProofError("bad_proof", f"proof purpose must be {purpose}")
    try:
        created = parse_time(proof.get("created"))
        signature = multibase_decode(proof.get("proofValue"))
    except ValueError as error:
        raise ProofError("bad_proof", str(error)) from error
    options = {k: v for k, v in proof.items() if k != "proofValue"}
    document = dict(unsecured)
    if "@context" in options and options["@context"] != unsecured.get("@context"):
        raise ProofError("bad_proof", "proof @context must equal the document @context")
    data = hash_data(document, options)
    vm = proof.get("verificationMethod", "")
    did = vm.split("#", 1)[0] if isinstance(vm, str) else ""
    if suite == PQ_SUITE:
        try:
            raw = mldsa_public_from_did(did)
        except DidError as error:
            raise ProofError("bad_verification_method", str(error)) from error
        if vm != f"{did}#{did.split(':')[2][:48]}":
            raise ProofError("bad_verification_method", "unknown ML-DSA verification method")
        if len(signature) != MLDSA44_SIGNATURE_BYTES:
            raise ProofError("bad_proof", "ML-DSA-44 signatures are 2420 bytes")
        try:
            MLDSA44PublicKey.from_public_bytes(raw).verify(signature, data)
        except (InvalidSignature, ValueError) as error:
            raise ProofError("bad_signature", "ML-DSA signature does not verify") from error
        return SuiteResult(suite, did, vm, created)
    if resolver is None:
        resolver = Resolver()
    try:
        controller, raw = resolver.public_key(vm, purpose)
    except DidError as error:
        raise ProofError("bad_verification_method", str(error)) from error
    if len(signature) != 64:
        raise ProofError("bad_proof", "Ed25519 signatures are 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(signature, data)
    except (InvalidSignature, ValueError) as error:
        raise ProofError("bad_signature", "Ed25519 signature does not verify") from error
    return SuiteResult(suite, controller, vm, created)


@dataclass(frozen=True)
class HybridVerification:
    policy: str
    results: tuple[SuiteResult, ...]

    @property
    def classical(self) -> SuiteResult | None:
        return next((r for r in self.results if r.cryptosuite == EDDSA_SUITE), None)

    @property
    def post_quantum(self) -> SuiteResult | None:
        return next((r for r in self.results if r.cryptosuite == PQ_SUITE), None)


def verify_proofs(secured: dict, purpose: str, *, policy: str = "hybrid", resolver: Resolver | None = None,
                  bindings: dict[str, str] | None = None) -> HybridVerification:
    """Verify a single proof or a proof set under a migration policy.

    bindings maps an Ed25519 DID to the ML-DSA DID it is bound to (from verified
    key-binding credentials). Under `hybrid`, both suites must verify AND be bound.
    Every proof present must verify (an invalid extra proof fails the document).
    """
    if policy not in POLICIES:
        raise ValueError(f"policy must be one of {POLICIES}")
    if not isinstance(secured, dict):
        raise ProofError("bad_format", "secured document must be a JSON object")
    raw = secured.get("proof")
    proofs = raw if isinstance(raw, list) else [raw]
    if not proofs or len(proofs) > 2:
        raise ProofError("bad_proof", "one proof or a proof set of two is required")
    unsecured = {k: v for k, v in secured.items() if k != "proof"}
    results = tuple(_verify_one(unsecured, p, resolver, purpose) for p in proofs)
    suites = [r.cryptosuite for r in results]
    if len(set(suites)) != len(suites):
        raise ProofError("bad_proof", "duplicate cryptosuite in proof set")
    outcome = HybridVerification(policy, results)
    if policy == "pq" and outcome.post_quantum is None:
        raise ProofError("pq_required", "policy pq requires an mldsa44-jcs-2024 proof")
    if policy == "classical" and outcome.classical is None and outcome.post_quantum is None:
        raise ProofError("bad_proof", "no usable proof")
    if policy == "hybrid":
        if outcome.classical is None or outcome.post_quantum is None:
            raise ProofError("hybrid_required", "policy hybrid requires both eddsa-jcs-2022 and mldsa44-jcs-2024 proofs")
        bound = (bindings or {}).get(outcome.classical.controller)
        if bound != outcome.post_quantum.controller:
            raise ProofError("unbound_keys", "the classical and post-quantum keys are not bound to one principal")
    return outcome


# ---------------------------------------------------------------------- key binding
def create_key_binding(classical: DidSigner, pq: MldsaSigner, created: int, *, valid_until: int | None = None) -> dict:
    """A self-issued credential binding an Ed25519 did:key and an ML-DSA did:key, signed by BOTH."""
    credential = {
        "@context": [VC_CONTEXT],
        "type": ["VerifiableCredential", KEY_BINDING_TYPE],
        "issuer": classical.did,
        "validFrom": format_time(created),
        "credentialSubject": {"id": classical.did, "alsoKnownAs": [pq.did], "migration": "hybrid-ed25519-mldsa44"},
    }
    if valid_until is not None:
        credential["validUntil"] = format_time(valid_until)
    return add_hybrid_proofs(credential, classical, pq, "assertionMethod", created)


def verify_key_binding(binding: dict, *, resolver: Resolver | None = None, now: int | None = None) -> tuple[str, str]:
    """Return (ed25519_did, mldsa_did) if the binding is valid; raises ProofError."""
    subject = binding.get("credentialSubject") if isinstance(binding, dict) else None
    if not isinstance(subject, dict) or KEY_BINDING_TYPE not in (binding.get("type") or []):
        raise ProofError("bad_format", "not an AutheoKeyBinding credential")
    aka = subject.get("alsoKnownAs")
    if not isinstance(aka, list) or len(aka) != 1 or binding.get("issuer") != subject.get("id"):
        raise ProofError("bad_format", "binding must be self-issued with exactly one alsoKnownAs")
    classical_did, pq_did = subject["id"], aka[0]
    result = verify_proofs(binding, "assertionMethod", policy="hybrid", resolver=resolver, bindings={classical_did: pq_did})
    if result.classical.controller != classical_did or result.post_quantum.controller != pq_did:
        raise ProofError("unbound_keys", "proofs are not from the bound keys")
    if now is not None:
        if parse_time(binding["validFrom"]) > now:
            raise ProofError("not_yet_valid")
        if "validUntil" in binding and parse_time(binding["validUntil"]) < now:
            raise ProofError("expired")
    return classical_did, pq_did
