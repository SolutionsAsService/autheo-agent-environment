"""Experimental v3 PQ vectors: Python and Node (node:crypto ML-DSA) must agree."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from autheo_agent_environment.data_integrity import ProofError
from autheo_agent_environment.pqc import verify_proofs

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "autheo-v3-pq-vectors.json"
NODE = shutil.which("node")


def _cases():
    return json.loads(VECTORS.read_text())["cases"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_python_agrees_with_vectors(case):
    try:
        verify_proofs(case["document"], "assertionMethod", policy=case["policy"], bindings=case["bindings"])
        ok = True
    except ProofError:
        ok = False
    assert ok is case["valid"]


def _node_has_mldsa() -> bool:
    if not NODE:
        return False
    probe = subprocess.run([NODE, "-e", "require('crypto').generateKeyPairSync('ml-dsa-44')"], capture_output=True)
    return probe.returncode == 0


@pytest.mark.skipif(not _node_has_mldsa(), reason="Node >= 24 with ML-DSA required")
def test_node_agrees_with_vectors():
    result = subprocess.run([NODE, str(ROOT / "interop" / "js" / "verify-v3-pq-vectors.mjs"), str(VECTORS)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr + result.stdout
