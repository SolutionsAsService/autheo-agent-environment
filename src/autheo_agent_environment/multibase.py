"""Pure implementations of the small encodings did:key needs: base58btc multibase and multicodec.

* base58btc uses the Bitcoin alphabet (draft-msporny-base58); leading zero bytes
  map to leading "1" characters. Multibase prefixes it with "z".
* multicodec prefixes are unsigned LEB128 varints (multiformats unsigned-varint);
  Ed25519 public keys use 0xed (bytes ed 01), Ed25519 private keys 0x1300
  (bytes 80 26) and X25519 public keys 0xec (bytes ec 01).

No third-party dependency: every function is checked against published vectors in
tests/test_did.py and tests/vectors/autheo-v2-vectors.json.
"""

from __future__ import annotations

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {character: value for value, character in enumerate(ALPHABET)}
# Bounded to keep base58 decoding cheap; 8192 fits ML-DSA-87 signatures (4627 bytes ≈ 6.3k chars).
MAX_ENCODED = 8192

ED25519_PUB = 0xED
ED25519_PRIV = 0x1300
X25519_PUB = 0xEC


def b58encode(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("base58 input must be bytes")
    zeros = len(data) - len(bytes(data).lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    out = []
    while number:
        number, remainder = divmod(number, 58)
        out.append(ALPHABET[remainder])
    return "1" * zeros + "".join(reversed(out))


def b58decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > MAX_ENCODED:
        raise ValueError("invalid base58 input")
    number = 0
    for character in text:
        value = _INDEX.get(character)
        if value is None:
            raise ValueError("invalid base58 character")
        number = number * 58 + value
    zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * zeros + body


def multibase_encode(data: bytes) -> str:
    """Multibase base58btc ("z" prefix); the only multibase form Autheo accepts."""
    return "z" + b58encode(data)


def multibase_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text.startswith("z") or len(text) < 2:
        raise ValueError("only base58btc multibase ('z' prefix) is supported")
    return b58decode(text[1:])


def varint_encode(value: int) -> bytes:
    if type(value) is not int or value < 0 or value >= 2**63:
        raise ValueError("varint must be a non-negative 63-bit integer")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def varint_decode(data: bytes) -> tuple[int, int]:
    """Return (value, bytes consumed). Rejects non-minimal encodings and more than 9 bytes."""
    value = shift = 0
    for index, byte in enumerate(bytes(data[:9])):
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if index and byte == 0:
                raise ValueError("non-minimal varint")
            return value, index + 1
        shift += 7
    raise ValueError("truncated or overlong varint")


def multicodec_wrap(code: int, payload: bytes) -> bytes:
    return varint_encode(code) + bytes(payload)


def multicodec_unwrap(data: bytes) -> tuple[int, bytes]:
    code, used = varint_decode(data)
    return code, bytes(data[used:])
