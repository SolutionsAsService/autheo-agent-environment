"""Offline receipt-chain verification against an operator-pinned public key."""

import argparse
import hashlib
import json
from pathlib import Path

from .signing import read_public, verify


def verify_archive(
    archive: dict, public_key, issuer: str, environment: str, expected_head=None, kid="demo-v1"
):
    if (
        not isinstance(archive, dict)
        or set(archive) != {"receipts"}
        or not isinstance(archive["receipts"], list)
    ):
        raise ValueError("Invalid audit archive")
    previous, ids = "0" * 64, set()
    for sequence, token in enumerate(archive["receipts"], 1):
        claims = verify(token, "receipt", public_key, issuer, environment, kid, historical=True)
        body = claims["body"]
        if (
            body.get("sequence") != sequence
            or body.get("previous_hash") != previous
            or body.get("executed") is not False
            or body.get("request_id") in ids
        ):
            raise ValueError("Audit chain integrity failure")
        ids.add(body["request_id"])
        previous = hashlib.sha256((previous + token).encode()).hexdigest()
    if expected_head is not None and previous != expected_head:
        raise ValueError("Audit head differs from external checkpoint")
    return {
        "signature_chain_verified": True,
        "count": len(ids),
        "head": previous,
        "immutable": False,
        "actual_actions_proven": False,
        "external_checkpoint_matched": expected_head is not None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--expected-head")
    args = parser.parse_args()
    # Local operator utility; bound input to keep malformed files from exhausting memory.
    if args.archive.stat().st_size > 10_000_000 or args.public_key.stat().st_size > 4096:
        parser.error("Input exceeds size limit")
    result = verify_archive(
        json.loads(args.archive.read_text()),
        read_public(args.public_key.read_text()),
        args.issuer,
        args.environment,
        args.expected_head,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
