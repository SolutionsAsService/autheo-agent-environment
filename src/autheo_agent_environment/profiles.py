"""Tunable post-quantum security profiles (experimental, v3 draft).

A profile picks the ML-DSA signature strength, the ML-KEM key-agreement strength and the
verifier policy together, so operators trade size/speed against margin in one setting:

| profile    | signature  | KEM          | NIST cat. | pub key / sig bytes | when to use |
| ---------- | ---------- | ------------ | --------- | ------------------- | ----------- |
| compact    | ML-DSA-44  | ML-KEM-768   | 2         | 1312 / 2420         | high-volume agent traffic, constrained devices, short-lived credentials |
| balanced   | ML-DSA-65  | ML-KEM-768   | 3         | 1952 / 3309         | default: delegations, receipts, institutional APIs |
| max        | ML-DSA-87  | ML-KEM-1024  | 5         | 2592 / 4627         | roots, long-lived evidence, regulated / banking anchors (CNSA 2.0 levels) |

All profiles are hybrid with Ed25519/X25519 until PQ-only is explicitly chosen
(`policy="pq"`). Choose with AUTHEO_SECURITY_PROFILE or per environment/tenant.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .pqc import MLDSA, POLICIES


@dataclass(frozen=True)
class SecurityProfile:
    name: str
    mldsa_level: int
    mlkem_level: int
    policy: str
    min_category: int
    summary: str

    def __post_init__(self) -> None:
        if self.mldsa_level not in MLDSA or self.mlkem_level not in (768, 1024) or self.policy not in POLICIES:
            raise ValueError(f"invalid security profile {self.name}")
        if self.min_category > MLDSA[self.mldsa_level].nist_category:
            raise ValueError("profile would reject its own signatures")

    @property
    def signature_bytes(self) -> int:
        return MLDSA[self.mldsa_level].signature_bytes

    @property
    def public_key_bytes(self) -> int:
        return MLDSA[self.mldsa_level].public_bytes

    def as_dict(self) -> dict:
        return {"name": self.name, "signature": f"ML-DSA-{self.mldsa_level}", "kem": f"ML-KEM-{self.mlkem_level}",
                "policy": self.policy, "minCategory": self.min_category, "signatureBytes": self.signature_bytes,
                "publicKeyBytes": self.public_key_bytes, "summary": self.summary}


PROFILES: dict[str, SecurityProfile] = {
    "compact": SecurityProfile("compact", 44, 768, "hybrid", 2, "smallest PQ keys and signatures; NIST category 2"),
    "balanced": SecurityProfile("balanced", 65, 768, "hybrid", 3, "default; NIST category 3 signatures, category 3 KEM"),
    "max": SecurityProfile("max", 87, 1024, "hybrid", 5, "largest margin; NIST category 5 (CNSA 2.0 parameter sets)"),
}
DEFAULT_PROFILE = "balanced"


def get_profile(name: str | None = None) -> SecurityProfile:
    """Profile by name, else AUTHEO_SECURITY_PROFILE, else 'balanced'. Unknown names are errors."""
    chosen = (name or os.getenv("AUTHEO_SECURITY_PROFILE") or DEFAULT_PROFILE).strip().lower()
    if chosen not in PROFILES:
        raise ValueError(f"unknown security profile {chosen!r}; choose one of {sorted(PROFILES)}")
    return PROFILES[chosen]


def custom_profile(name: str, *, mldsa_level: int, mlkem_level: int = 768, policy: str = "hybrid",
                   min_category: int | None = None) -> SecurityProfile:
    """Fine-grained tuning when the presets don't fit (validated like the presets)."""
    return SecurityProfile(name, mldsa_level, mlkem_level, policy,
                           MLDSA[mldsa_level].nist_category if min_category is None else min_category, "custom")
