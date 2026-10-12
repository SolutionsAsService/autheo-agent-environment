r"""RFC 8785 JSON Canonicalization Scheme (JCS) for the Autheo v2 value profile.

eddsa-jcs-2022 (W3C Data Integrity EdDSA Cryptosuites v1.0) hashes JCS output, so
this module implements RFC 8785 exactly for the values Autheo v2 documents use:

* objects: members sorted by the UTF-16 code units of their keys (RFC 8785 3.2.3),
  no whitespace; keys must be strings and unique;
* strings: ECMAScript JSON.stringify rules - escape quote, backslash, the short
  escapes b f n r t, every other control character U+0000-U+001F as lowercase
  \u00xx; everything else (including DEL and non-ASCII) is emitted as UTF-8;
  lone surrogates are rejected;
* numbers: integers in the IEEE-754 safe range only. JCS itself serialises any
  double with the ECMAScript algorithm; Autheo v2 documents never contain
  non-integers, so floats are rejected rather than half-supported;
* true, false, null.

This differs from the v1 "autheo-cjson/1" digest format (canonical.py), which
additionally ASCII-escapes non-ASCII characters. v1 digests are unchanged.
"""

from __future__ import annotations

import hashlib

MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 32
_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _string(value: str) -> str:
    out = ['"']
    for character in value:
        code = ord(character)
        if character in _SHORT:
            out.append(_SHORT[character])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("JCS rejects lone surrogates")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _serialize(value, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise ValueError("JCS nesting is too deep")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError("JCS profile allows IEEE-754 safe integers only")
        return str(value)
    if isinstance(value, float):
        raise ValueError("Autheo v2 JCS profile forbids non-integer numbers")
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError("JCS object keys must be strings")
        keys = sorted(value, key=_utf16_key)
        return "{" + ",".join(_string(k) + ":" + _serialize(value[k], depth + 1) for k in keys) + "}"
    raise ValueError(f"JCS cannot encode {type(value).__name__}")


def canonicalize(value) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a JSON value."""
    return _serialize(value, 0).encode("utf-8")


def jcs_sha256(value) -> bytes:
    return hashlib.sha256(canonicalize(value)).digest()


def jcs_digest(value) -> str:
    """Lowercase hex SHA-256 of the JCS bytes; the v2 document digest."""
    return hashlib.sha256(canonicalize(value)).hexdigest()
