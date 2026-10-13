"""Post-quantum and hybrid proofs (Autheo v3 draft, experimental): ML-DSA did:key at a
tunable strength (ML-DSA-44 / -65 / -87), the `mldsa{44,65,87}-jcs-2024` Data Integrity
cryptosuites, hybrid proof sets and cross-signed key bindings. Pick a strength through a
security profile (`profiles.py`); verifiers can demand a minimum NIST category.

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
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA44PublicKey,
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
    MLDSA87PrivateKey,
    MLDSA87PublicKey,
)

from .data_integrity import CRYPTOSUITE as EDDSA_SUITE
from .data_integrity import PROOF_TYPE, ProofError, format_time, hash_data, parse_time
from .did import DidError, DidSigner, Resolver
from .multibase import multibase_decode, multibase_encode, multicodec_unwrap, multicodec_wrap


@dataclass(frozen=True)
class MldsaParams:
    """One FIPS 204 parameter set. Bigger = more margin, bigger keys/signatures, slower."""

    level: int            # 44 / 65 / 87
    nist_category: int    # 2 / 3 / 5
    multicodec: int       # mldsa-44-pub 0x1210, mldsa-65-pub 0x1211, mldsa-87-pub 0x1212 (multicodec table, draft)
    public_bytes: int
    signature_bytes: int
    suite: str
    private_cls: type
    public_cls: type


MLDSA = {
    44: MldsaParams(44, 2, 0x1210, 1312, 2420, "mldsa44-jcs-2024", MLDSA44PrivateKey, MLDSA44PublicKey),
    65: MldsaParams(65, 3, 0x1211, 1952, 3309, "mldsa65-jcs-2024", MLDSA65PrivateKey, MLDSA65PublicKey),
    87: MldsaParams(87, 5, 0x1212, 2592, 4627, "mldsa87-jcs-2024", MLDSA87PrivateKey, MLDSA87PublicKey),
}
_BY_CODEC = {p.multicodec: p for p in MLDSA.values()}
_BY_SUITE = {p.suite: p for p in MLDSA.values()}
_BY_PUBLIC_LEN = {p.public_bytes: p for p in MLDSA.values()}

MLDSA44_PUB = MLDSA[44].multicodec
MLDSA44_PUBLIC_BYTES = MLDSA[44].public_bytes
MLDSA44_SIGNATURE_BYTES = MLDSA[44].signature_bytes
PQ_SUITE = MLDSA[44].suite
PQ_SUITES = tuple(p.suite for p in MLDSA.values())
SUITES = (EDDSA_SUITE, *PQ_SUITES)
POLICIES = ("classical", "hybrid", "pq")
KEY_BINDING_TYPE = "AutheoKeyBinding"
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
PROOF_MEMBERS = {"type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue", "@context"}
_MLDSA_DID = re.compile(r"^did:key:z[1-9A-HJ-NP-Za-km-z]{1700,3600}$")


def params(level: int) -> MldsaParams:
    if level not in MLDSA:
        raise ValueError(f"ML-DSA level must be one of {sorted(MLDSA)}")
    return MLDSA[level]


# ---------------------------------------------------------------------- ML-DSA did:key
def mldsa_did_from_public(raw: bytes) -> str:
    p = _BY_PUBLIC_LEN.get(len(raw))
    if p is None:
        raise DidError("invalidPublicKeyLength", "ML-DSA public keys are 1312, 1952 or 2592 bytes")
    return "did:key:" + multibase_encode(multicodec_wrap(p.multicodec, raw))


def mldsa_key_info(did: str) -> tuple[MldsaParams, bytes]:
    """(parameter set, raw public key) for an ML-DSA did:key."""
    if not isinstance(did, str) or not _MLDSA_DID.match(did):
        raise DidError("invalidDid", "not an ML-DSA did:key")
    try:
        code, raw = multicodec_unwrap(multibase_decode(did.split(":")[2]))
    except ValueError as error:
        raise DidError("invalidDid", str(error)) from error
    p = _BY_CODEC.get(code)
    if p is None or len(raw) != p.public_bytes:
        raise DidError("unsupportedPublicKeyType", "expected mldsa-44/65/87-pub (0x1210-0x1212)")
    if mldsa_did_from_public(raw) != did:
        raise DidError("invalidDid", "non-canonical did:key encoding")
    return p, raw


def mldsa_public_from_did(did: str) -> bytes:
    return mldsa_key_info(did)[1]


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
    """ML-DSA private key plus the did:key, verification method and suite it signs for."""

    did: str
    verification_method: str
    key: object
    level: int = 44

    @property
    def suite(self) -> str:
        return MLDSA[self.level].suite

    def sign(self, data: bytes) -> bytes:
        return self.key.sign(data)


@dataclass(frozen=True)
class MldsaKey:
    """An ML-DSA key pair at level 44, 65 or 87; creating one needs nobody's permission."""

    key: object
    level: int = 44

    @classmethod
    def generate(cls, level: int = 44) -> MldsaKey:
        return cls(params(level).private_cls.generate(), level)

    @classmethod
    def from_seed(cls, seed: bytes, level: int = 44) -> MldsaKey:
        if len(seed) != 32:
            raise ValueError("ML-DSA seeds are 32 bytes")
        return cls(params(level).private_cls.from_seed_bytes(seed), level)

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
        return MldsaSigner(self.did, self.verification_method, self.key, self.level)


# ---------------------------------------------------------------------- proofs
def _proof_options(signer, suite: str, purpose: str, created: int, document: dict) -> dict:
    options = {"type": PROOF_TYPE, "cryptosuite": suite, "created": format_time(created),
               "verificationMethod": signer.verification_method, "proofPurpose": purpose}
    if "@context" in document:
        options["@context"] = document["@context"]
    return options


def _make_proof(document: dict, signer, purpose: str, created: int) -> dict:
    suite = signer.suite if isinstance(signer, MldsaSigner) else EDDSA_SUITE
    options = _proof_options(signer, suite, purpose, created, document)
    return {**options, "proofValue": multibase_encode(signer.sign(hash_data(document, options)))}


def add_hybrid_proofs(document: dict, classical: DidSigner, pq: MldsaSigner, purpose: str, created: int) -> dict:
    """Attach a proof set [eddsa-jcs-2022, mldsaNN-jcs-2024] over the same unsecured document."""
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
    nist_category: int = 1  # Ed25519 ~ classical 128-bit; 0 quantum resistance


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
    if suite in PQ_SUITES:
        try:
            p, raw = mldsa_key_info(did)
        except DidError as error:
            raise ProofError("bad_verification_method", str(error)) from error
        if p.suite != suite:
            raise ProofError("bad_verification_method", f"{suite} proof made with an ML-DSA-{p.level} key")
        if vm != f"{did}#{did.split(':')[2][:48]}":
            raise ProofError("bad_verification_method", "unknown ML-DSA verification method")
        if len(signature) != p.signature_bytes:
            raise ProofError("bad_proof", f"ML-DSA-{p.level} signatures are {p.signature_bytes} bytes")
        try:
            p.public_cls.from_public_bytes(raw).verify(signature, data)
        except (InvalidSignature, ValueError) as error:
            raise ProofError("bad_signature", "ML-DSA signature does not verify") from error
        return SuiteResult(suite, did, vm, created, p.nist_category)
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
        return next((r for r in self.results if r.cryptosuite in PQ_SUITES), None)


def verify_proofs(secured: dict, purpose: str, *, policy: str = "hybrid", resolver: Resolver | None = None,
                  bindings: dict[str, str] | None = None, min_category: int = 2) -> HybridVerification:
    """Verify a single proof or a proof set under a migration policy.

    bindings maps an Ed25519 DID to the ML-DSA DID it is bound to (from verified
    key-binding credentials). Under `hybrid`, both suites must verify AND be bound.
    Every proof present must verify (an invalid extra proof fails the document).
    min_category is the minimum NIST category for the post-quantum proof (2 = ML-DSA-44,
    3 = ML-DSA-65, 5 = ML-DSA-87); weaker PQ proofs are rejected, never silently accepted.
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
    if len(set(suites)) != len(suites) or sum(s in PQ_SUITES for s in suites) > 1:
        raise ProofError("bad_proof", "a proof set holds at most one classical and one post-quantum proof")
    outcome = HybridVerification(policy, results)
    pq_result = outcome.post_quantum
    if pq_result is not None and pq_result.nist_category < min_category:
        raise ProofError("pq_level_too_low", f"post-quantum proof is NIST category {pq_result.nist_category}, policy requires {min_category}")
    if policy == "pq" and outcome.post_quantum is None:
        raise ProofError("pq_required", "policy pq requires an ML-DSA proof")
    if policy == "classical" and outcome.classical is None and outcome.post_quantum is None:
        raise ProofError("bad_proof", "no usable proof")
    if policy == "hybrid":
        if outcome.classical is None or outcome.post_quantum is None:
            raise ProofError("hybrid_required", "policy hybrid requires both eddsa-jcs-2022 and ML-DSA proofs")
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
        "credentialSubject": {"id": classical.did, "alsoKnownAs": [pq.did], "migration": f"hybrid-ed25519-mldsa{pq.level}"},
    }
    if valid_until is not None:
        credential["validUntil"] = format_time(valid_until)
    return add_hybrid_proofs(credential, classical, pq, "assertionMethod", created)


def verify_key_binding(binding: dict, *, resolver: Resolver | None = None, now: int | None = None,
                       min_category: int = 2) -> tuple[str, str]:
    """Return (ed25519_did, mldsa_did) if the binding is valid; raises ProofError."""
    subject = binding.get("credentialSubject") if isinstance(binding, dict) else None
    if not isinstance(subject, dict) or KEY_BINDING_TYPE not in (binding.get("type") or []):
        raise ProofError("bad_format", "not an AutheoKeyBinding credential")
    aka = subject.get("alsoKnownAs")
    if not isinstance(aka, list) or len(aka) != 1 or binding.get("issuer") != subject.get("id"):
        raise ProofError("bad_format", "binding must be self-issued with exactly one alsoKnownAs")
    classical_did, pq_did = subject["id"], aka[0]
    result = verify_proofs(binding, "assertionMethod", policy="hybrid", resolver=resolver, bindings={classical_did: pq_did},
                           min_category=min_category)
    if result.classical.controller != classical_did or result.post_quantum.controller != pq_did:
        raise ProofError("unbound_keys", "proofs are not from the bound keys")
    if now is not None:
        if parse_time(binding["validFrom"]) > now:
            raise ProofError("not_yet_valid")
        if "validUntil" in binding and parse_time(binding["validUntil"]) < now:
            raise ProofError("expired")
    return classical_did, pq_did
