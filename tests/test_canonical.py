import hashlib
import json

import pytest

from autheo_agent_environment.canonical import (
    MAX_SAFE_INTEGER,
    ZERO_HASH,
    canonical_json,
    chain_hash,
    digest,
    is_hex64,
)
from autheo_agent_environment.signing import digest as legacy_digest


def test_canonical_bytes_are_sorted_compact_and_ascii():
    value = {"b": 1, "a": [True, None, "x"], "B": {"z": 0, "y": -1}}
    assert canonical_json(value) == b'{"B":{"y":-1,"z":0},"a":[true,null,"x"],"b":1}'
    assert canonical_json({"s": "caf\u00e9 \U0001d11e \x7f/"}) == b'{"s":"caf\\u00e9 \\ud834\\udd1e \\u007f/"}'
    assert canonical_json({"s": "\n\t\x01\"\\"}) == b'{"s":"\\n\\t\\u0001\\"\\\\"}'


def test_digest_is_unchanged_from_the_01_implementation():
    value = {"agent_id": "agent:one", "amount_minor": 40, "scopes": ["a", "b"]}
    old = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    assert digest(value) == old == legacy_digest(value)


@pytest.mark.parametrize(
    "value",
    [1.5, float("nan"), {"n": MAX_SAFE_INTEGER + 1}, {"n": -MAX_SAFE_INTEGER - 1}, {1: "x"}, {"s": b"x"}],
)
def test_non_canonical_values_are_rejected(value):
    with pytest.raises(ValueError):
        canonical_json(value)


def test_nesting_limit():
    value = []
    for _ in range(40):
        value = [value]
    with pytest.raises(ValueError, match="deep"):
        canonical_json(value)


def test_chain_hash_rule_and_validation():
    token = "a.b.c"
    assert chain_hash(ZERO_HASH, token) == hashlib.sha256((ZERO_HASH + token).encode()).hexdigest()
    assert is_hex64(ZERO_HASH) and not is_hex64("A" * 64) and not is_hex64(None)
    with pytest.raises(ValueError):
        chain_hash("xyz", token)
