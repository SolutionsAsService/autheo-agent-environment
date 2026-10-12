r"""Autheo canonical JSON v1 ("autheo-cjson/1") and the digests built on it.

The exact byte format is specified in docs/SPEC-SIGNATURES.md so that other
languages (the JARVIS kernel is JavaScript) can reproduce every digest:

* UTF-8 (in practice pure ASCII) JSON text with no insignificant whitespace;
* object members sorted by key, compared as Unicode code points (all keys used
  by Autheo documents are ASCII);
* every character outside printable ASCII (0x20-0x7E) is escaped: the short
  JSON escapes \b \f \n \r \t \" \\ where they exist, otherwise \uXXXX with
  lowercase hex (this includes DEL 0x7F; code points above U+FFFF become a
  UTF-16 surrogate pair); the solidus "/" is not escaped;
* integers only, within the IEEE-754 safe range [-(2**53-1), 2**53-1]; floats,
  NaN and infinities are rejected; booleans and null are literals.

For the values Autheo emits (ASCII keys, safe integers, strings) this is
byte-compatible with RFC 8785 (JCS) after JCS output is ASCII-escaped.
Signatures are never computed over re-serialized JSON: they cover the exact
compact JWS bytes (see signing.py and the specification).
"""

from __future__ import annotations

import hashlib
import json

CANONICAL_JSON_ID = "autheo-cjson/1"
MAX_SAFE_INTEGER = 2**53 - 1
ZERO_HASH = "0" * 64
_HEX = frozenset("0123456789abcdef")


def _check(value, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("Canonical JSON nesting is too deep")
    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("Canonical JSON integers must be within the IEEE-754 safe range")
        return
    if isinstance(value, float):
        raise ValueError("Canonical JSON forbids floating-point numbers")
    if isinstance(value, (list, tuple)):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Canonical JSON object keys must be strings")
            _check(item, depth + 1)
        return
    raise ValueError(f"Canonical JSON cannot encode {type(value).__name__}")


def canonical_json(value) -> bytes:
    """Return the canonical autheo-cjson/1 bytes for a JSON-compatible value."""
    _check(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(value) -> str:
    """Lowercase hex SHA-256 of the canonical JSON bytes."""
    return hashlib.sha256(canonical_json(value)).hexdigest()


def is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def chain_hash(previous_hash: str, token: str) -> str:
    """Receipt-chain link: sha256(ascii(previous_hash_hex) || ascii(compact_jws))."""
    if not is_hex64(previous_hash):
        raise ValueError("Previous hash must be 64 lowercase hex characters")
    return hashlib.sha256((previous_hash + token).encode("ascii")).hexdigest()
