"""Hybrid post-quantum key agreement for sealed agent payloads (experimental, v3 draft).

X25519 + ML-KEM-768/1024 (FIPS 203), combined like X-Wing / the TLS hybrid groups in
draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768): both shared secrets plus the ciphertexts and
public keys go through SHA3-256, then HKDF-SHA256 -> AES-256-GCM. Breaking it needs BOTH
X25519 and ML-KEM broken. Use for checkpoint handoffs and other agent-to-agent payloads that
must stay confidential past the arrival of a quantum computer ("harvest now, decrypt later").

Envelope (JSON, all bytes base64url): {"alg": "X25519-MLKEM768-A256GCM", "kid", "epk", "ct",
"iv", "data"}. AAD is caller-supplied and authenticated.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_KEM = {768: (mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, 1184), 1024: (mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey, 1568)}
_LABEL = b"autheo-hybrid-kem/v1"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(v: str) -> bytes:
    if not isinstance(v, str):
        raise ValueError("expected base64url string")
    return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))


def _raw(pub) -> bytes:
    return pub.public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)


def alg_name(level: int) -> str:
    return f"X25519-MLKEM{level}-A256GCM"


@dataclass(frozen=True)
class HybridKemPublic:
    level: int
    x25519: bytes
    mlkem: bytes

    def encode(self) -> str:
        return _b64(self.x25519 + self.mlkem)

    @property
    def kid(self) -> str:
        return hashlib.sha256(self.x25519 + self.mlkem).hexdigest()[:32]

    @classmethod
    def decode(cls, value: str, level: int) -> HybridKemPublic:
        raw = _unb64(value)
        if level not in _KEM or len(raw) != 32 + _KEM[level][2]:
            raise ValueError("bad hybrid KEM public key")
        return cls(level, raw[:32], raw[32:])


@dataclass(frozen=True)
class HybridKemKey:
    level: int
    x25519: X25519PrivateKey
    mlkem: object

    @classmethod
    def generate(cls, level: int = 768) -> HybridKemKey:
        if level not in _KEM:
            raise ValueError("ML-KEM level must be 768 or 1024")
        return cls(level, X25519PrivateKey.generate(), _KEM[level][0].generate())

    @property
    def public(self) -> HybridKemPublic:
        return HybridKemPublic(self.level, _raw(self.x25519.public_key()), _raw(self.mlkem.public_key()))


def _combine(ss_m: bytes, ss_x: bytes, ct: bytes, epk: bytes, recipient: HybridKemPublic) -> bytes:
    secret = hashlib.sha3_256(_LABEL + ss_m + ss_x + ct + epk + recipient.x25519 + recipient.mlkem).digest()
    return HKDF(SHA256(), 32, salt=None, info=_LABEL + b"/aes-256-gcm").derive(secret)


def seal(recipient: HybridKemPublic, plaintext: bytes, aad: bytes = b"") -> dict:
    eph = X25519PrivateKey.generate()
    epk = _raw(eph.public_key())
    ss_x = eph.exchange(X25519PublicKey.from_public_bytes(recipient.x25519))
    ss_m, ct = _KEM[recipient.level][1].from_public_bytes(recipient.mlkem).encapsulate()
    key = _combine(ss_m, ss_x, ct, epk, recipient)
    iv = os.urandom(12)
    alg = alg_name(recipient.level)
    data = AESGCM(key).encrypt(iv, plaintext, alg.encode() + b"|" + aad)
    return {"alg": alg, "kid": recipient.kid, "epk": _b64(epk), "ct": _b64(ct), "iv": _b64(iv), "data": _b64(data)}


def open_sealed(key: HybridKemKey, envelope: dict, aad: bytes = b"") -> bytes:
    """Decrypt; raises ValueError on any mismatch (wrong key, tampering, wrong AAD, wrong level)."""
    try:
        if envelope.get("alg") != alg_name(key.level) or envelope.get("kid") != key.public.kid:
            raise ValueError("envelope is not for this key")
        epk, ct, iv, data = (_unb64(envelope[k]) for k in ("epk", "ct", "iv", "data"))
        ss_x = key.x25519.exchange(X25519PublicKey.from_public_bytes(epk))
        ss_m = key.mlkem.decapsulate(ct)
        aes = _combine(ss_m, ss_x, ct, epk, key.public)
        return AESGCM(aes).decrypt(iv, data, envelope["alg"].encode() + b"|" + aad)
    except ValueError:
        raise
    except Exception as error:  # InvalidTag, KeyError, bad lengths
        raise ValueError("cannot open envelope") from error
