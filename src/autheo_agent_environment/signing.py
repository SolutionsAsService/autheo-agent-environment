"""Ed25519 JWS via maintained PyJWT/cryptography implementations; no custom crypto."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_TOKEN_BYTES = 131072
MAX_TTL = {
    "passport": 86400,
    "mandate": 3600,
    "request": 300,
    "handoff": 300,
    "trust-snapshot": 300,
    "receipt": 86400,
}


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def public_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def read_public(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Only Ed25519 public keys are accepted")
    return key


@dataclass(frozen=True)
class Signer:
    issuer: str
    key: Ed25519PrivateKey
    kid: str = "demo-v1"

    @classmethod
    def generate(cls, issuer: str):
        return cls(issuer, Ed25519PrivateKey.generate())

    @property
    def public_key(self):
        return self.key.public_key()

    def issue(self, kind: str, subject: str, audience: str, body: dict, ttl: int = 300) -> str:
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL[kind]:
            raise ValueError("Invalid token lifetime")
        now = int(time.time())
        claims = dict(
            iss=self.issuer,
            sub=subject,
            aud=audience,
            iat=now,
            nbf=now,
            exp=now + ttl,
            jti=str(uuid4()),
            body=body,
        )
        return jwt.encode(
            claims, self.key, algorithm="EdDSA", headers={"typ": f"autheo-{kind}+jwt", "kid": self.kid}
        )


def verify(
    token: str,
    kind: str,
    key: Ed25519PublicKey,
    issuer: str,
    audience: str,
    kid: str = "demo-v1",
    historical: bool = False,
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
            "verify_exp": not historical,
            "strict_aud": True,
        },
    )
    if any(type(claims[k]) is not int for k in ("iat", "nbf", "exp")):
        raise ValueError("Timestamps must be integer seconds")
    if not 0 < claims["exp"] - claims["iat"] <= MAX_TTL[kind] or claims["nbf"] != claims["iat"]:
        raise ValueError("Invalid token validity window")
    if not isinstance(claims["body"], dict) or not isinstance(claims["jti"], str) or not claims["jti"]:
        raise ValueError("Invalid document body or identifier")
    return claims
