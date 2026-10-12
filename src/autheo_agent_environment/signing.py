"""Ed25519 JWS via maintained PyJWT/cryptography implementations; no custom crypto.

Signature format (normative text: docs/SPEC-SIGNATURES.md): every Autheo document
is an RFC 7515 compact JWS, RFC 8037 "EdDSA" with an Ed25519 key, header
{"alg":"EdDSA","kid":<key id>,"typ":"autheo-<kind>+jwt"}, and a JWT-style claim
set {iss, sub, aud, iat, nbf, exp, jti, body}. Verifiers check the signature over
the exact ASCII bytes "<header b64url>.<payload b64url>" and never re-serialize.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import digest  # noqa: F401  (re-exported for backwards compatibility)

MAX_TOKEN_BYTES = 131072
CLOCK_SKEW_SECONDS = 2
MAX_TTL = {
    "passport": 86400,
    "mandate": 3600,
    "request": 300,
    "handoff": 300,
    "trust-snapshot": 300,
    "receipt": 86400,
    "outcome": 300,
}
DOCUMENT_KINDS = tuple(MAX_TTL)
LEGACY_KID = "demo-v1"


def public_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def read_public(pem: str) -> Ed25519PublicKey:
    if not isinstance(pem, str) or len(pem) > 4096:
        raise ValueError("Invalid public key")
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Only Ed25519 public keys are accepted")
    return key


def private_pem(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def read_private(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Only Ed25519 private keys are accepted")
    return key


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_jwk(key: Ed25519PublicKey, kid: str) -> dict:
    """RFC 8037 OKP JWK for interoperable verification (e.g. Node crypto / jose)."""
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw_public(key)), "kid": kid, "alg": "EdDSA"}


def key_fingerprint(key: Ed25519PublicKey) -> str:
    """sha256 over SPKI DER bytes, base64url; same construction as Paperclip agent key IDs."""
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + b64url(hashlib.sha256(der).digest())


def agent_kid(token: str, key: Ed25519PublicKey) -> str:
    """Key id expected on agent-signed documents (request, outcome).

    v1: the key fingerprint "sha256:<b64url(sha256(SPKI DER))>" of the passport-bound key
    (the same construction Paperclip uses for agent keyId). The 0.1 value "demo-v1" is
    still accepted. Any other kid is rejected by verify().
    """
    fingerprint = key_fingerprint(key)
    header = jwt.get_unverified_header(token)
    return header.get("kid") if header.get("kid") in {fingerprint, LEGACY_KID} else fingerprint


@dataclass(frozen=True)
class Signer:
    issuer: str
    key: Ed25519PrivateKey
    kid: str = "demo-v1"

    @classmethod
    def generate(cls, issuer: str, kid: str = LEGACY_KID):
        return cls(issuer, Ed25519PrivateKey.generate(), kid)

    @classmethod
    def for_agent(cls, agent_id: str, key: Ed25519PrivateKey):
        """Agent signer whose kid is its key fingerprint (schema v1 convention)."""
        return cls(agent_id, key, key_fingerprint(key.public_key()))

    @property
    def public_key(self):
        return self.key.public_key()

    def issue(
        self,
        kind: str,
        subject: str,
        audience: str,
        body: dict,
        ttl: int = 300,
        *,
        now: int | None = None,
        jti: str | None = None,
    ) -> str:
        """Sign a document. "now"/"jti" overrides exist only for deterministic test vectors."""
        if kind not in MAX_TTL:
            raise ValueError("Unknown document kind")
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL[kind]:
            raise ValueError("Invalid token lifetime")
        now = int(time.time()) if now is None else now
        claims = dict(
            iss=self.issuer,
            sub=subject,
            aud=audience,
            iat=now,
            nbf=now,
            exp=now + ttl,
            jti=jti or str(uuid4()),
            body=body,
        )
        return jwt.encode(
            claims, self.key, algorithm="EdDSA", headers={"typ": f"autheo-{kind}+jwt", "kid": self.kid}
        )


def unverified_claims(token: str) -> dict:
    """Decode WITHOUT verification, for routing only (e.g. locating a ledger). Never trust the result."""
    if not isinstance(token, str) or len(token.encode()) > MAX_TOKEN_BYTES:
        raise ValueError("Invalid token size")
    return jwt.decode(token, options={"verify_signature": False})


def verify(
    token: str,
    kind: str,
    key: Ed25519PublicKey,
    issuer: str,
    audience: str,
    kid: str = "demo-v1",
    historical: bool = False,
    now: int | None = None,
) -> dict:
    if not isinstance(token, str) or len(token.encode()) > MAX_TOKEN_BYTES:
        raise ValueError("Invalid token size")
    if historical and kind != "receipt":
        raise ValueError("Historical verification is for receipts only")
    header = jwt.get_unverified_header(token)
    if header.get("typ") != f"autheo-{kind}+jwt" or header.get("kid") != kid or header.get("crit"):
        raise ValueError("Invalid document type or key identifier")
    claims = jwt.decode(
        token,
        key,
        algorithms=["EdDSA"],
        issuer=issuer,
        audience=audience,
        options={
            "require": ["iss", "sub", "aud", "iat", "nbf", "exp", "jti", "body"],
            "verify_iat": False,
            "verify_nbf": False,
            "verify_exp": False,
            "strict_aud": True,
        },
    )
    if any(type(claims[k]) is not int for k in ("iat", "nbf", "exp")):
        raise ValueError("Timestamps must be integer seconds")
    now = int(time.time()) if now is None else now
    if not historical and claims["exp"] <= now:
        raise jwt.ExpiredSignatureError("Signature has expired")
    if claims["iat"] > now + CLOCK_SKEW_SECONDS or claims["nbf"] > now + CLOCK_SKEW_SECONDS:
        raise jwt.ImmatureSignatureError("Token validity starts too far in the future")
    if not 0 < claims["exp"] - claims["iat"] <= MAX_TTL[kind] or claims["nbf"] != claims["iat"]:
        raise ValueError("Invalid token validity window")
    if not isinstance(claims["body"], dict) or not isinstance(claims["jti"], str) or not claims["jti"]:
        raise ValueError("Invalid document body or identifier")
    return claims
