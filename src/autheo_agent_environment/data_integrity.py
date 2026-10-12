"""W3C Data Integrity proofs with the eddsa-jcs-2022 cryptosuite (Ed25519 + RFC 8785 JCS).

Implements "Add Proof" / "Verify Proof" of Data Integrity EdDSA Cryptosuites v1.0
section 3.3 for single proofs:

    proofConfig = proof options (type, cryptosuite, created, verificationMethod,
                  proofPurpose and, if the document has one, its @context)
    hashData    = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document without proof))
    proofValue  = "z" + base58btc(Ed25519.sign(hashData))

The verification key comes from resolving proof.verificationMethod (a DID URL) and
checking that the method is authorised for proof.proofPurpose in the DID document.
Tested against the W3C specification example (Appendix B.3) in the v2 vectors.

Autheo profile restrictions (docs/SPEC-DID.md section 3): exactly one proof object
(no proof sets/chains), "created" is required, timestamps use the exact form
YYYY-MM-DDTHH:MM:SSZ, and no other proof members are accepted.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .did import DidError, DidSigner, Resolver
from .jcs import canonicalize
from .multibase import multibase_decode, multibase_encode

PROOF_TYPE = "DataIntegrityProof"
CRYPTOSUITE = "eddsa-jcs-2022"
DATETIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PROOF_MEMBERS = {"type", "cryptosuite", "created", "verificationMethod", "proofPurpose", "proofValue", "@context"}
MAX_DOCUMENT_BYTES = 262144


class ProofError(ValueError):
    """A proof is malformed, uses the wrong key/purpose, or its signature does not verify."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


def format_time(epoch: int) -> str:
    if type(epoch) is not int or not 0 <= epoch < 253402300800:
        raise ValueError("timestamp out of range")
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value) -> int:
    if not isinstance(value, str) or not DATETIME.match(value):
        raise ValueError("timestamps must be YYYY-MM-DDTHH:MM:SSZ (UTC)")
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def hash_data(unsecured: dict, proof_config: dict) -> bytes:
    """Data Integrity eddsa-jcs-2022 hashing step: proof-config hash first, then document hash."""
    document = canonicalize(unsecured)
    if len(document) > MAX_DOCUMENT_BYTES:
        raise ProofError("document_too_large")
    return hashlib.sha256(canonicalize(proof_config)).digest() + hashlib.sha256(document).digest()


def add_proof(document: dict, signer: DidSigner, purpose: str, created: int) -> dict:
    """Return a copy of document with an eddsa-jcs-2022 DataIntegrityProof attached."""
    if not isinstance(document, dict) or "proof" in document:
        raise ValueError("document must be a JSON object without a proof")
    proof = {
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "created": format_time(created),
        "verificationMethod": signer.verification_method,
        "proofPurpose": purpose,
    }
    if "@context" in document:
        proof["@context"] = document["@context"]
    signature = signer.sign(hash_data(document, proof))
    return {**document, "proof": {**proof, "proofValue": multibase_encode(signature)}}


@dataclass(frozen=True)
class VerifiedProof:
    controller: str
    verification_method: str
    purpose: str
    created: int


def verify_proof(secured: dict, resolver: Resolver, purpose: str) -> VerifiedProof:
    """Verify the single eddsa-jcs-2022 proof on secured for the expected purpose; raises ProofError."""
    if not isinstance(secured, dict):
        raise ProofError("bad_format", "secured document must be a JSON object")
    proof = secured.get("proof")
    if not isinstance(proof, dict):
        raise ProofError("bad_proof", "exactly one proof object is required")
    unknown = set(proof) - PROOF_MEMBERS
    if unknown:
        raise ProofError("bad_proof", f"unsupported proof members: {sorted(unknown)}")
    if proof.get("type") != PROOF_TYPE or proof.get("cryptosuite") != CRYPTOSUITE:
        raise ProofError("bad_proof", "proof must be DataIntegrityProof / eddsa-jcs-2022")
    if proof.get("proofPurpose") != purpose:
        raise ProofError("bad_proof", f"proof purpose must be {purpose}")
    try:
        created = parse_time(proof.get("created"))
        signature = multibase_decode(proof.get("proofValue"))
    except ValueError as error:
        raise ProofError("bad_proof", str(error)) from error
    if len(signature) != 64:
        raise ProofError("bad_proof", "Ed25519 signatures are 64 bytes")
    options = {k: v for k, v in proof.items() if k != "proofValue"}
    unsecured = {k: v for k, v in secured.items() if k != "proof"}
    if "@context" in options:
        context, document_context = options["@context"], secured.get("@context")
        prefix = context if isinstance(context, list) else [context]
        current = document_context if isinstance(document_context, list) else [document_context]
        if current[: len(prefix)] != prefix:
            raise ProofError("bad_proof", "proof @context is not a prefix of the document @context")
        unsecured["@context"] = context
    try:
        controller, raw = resolver.public_key(proof["verificationMethod"], purpose)
    except DidError as error:
        raise ProofError("bad_verification_method", str(error)) from error
    try:
        data = hash_data(unsecured, options)
    except ValueError as error:
        raise ProofError("bad_format", str(error)) from error
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(signature, data)
    except (InvalidSignature, ValueError) as error:
        raise ProofError("bad_signature", "signature does not verify") from error
    return VerifiedProof(controller, proof["verificationMethod"], purpose, created)
