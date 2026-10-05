"""Retrieval measurement repro guard (opt-in rerun; pinned protocol integrity).

Always-run part: if benchmarks/retrieval/results.json exists, pins grid,
protocol hash vs config, source hashes, and the scale ordering
(10k median >= 1k median). Skips when no recorded results exist.

Rerun part (VERIFYCI_RETRIEVAL_RERUN=1): re-executes measure.py and asserts
same hashes/grid, median within +/-50%, tail within 3x. Never identical ns.
"""
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "benchmarks" / "retrieval" / "results.json"
CONFIG = ROOT / "benchmarks" / "retrieval" / "config.json"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_recorded():
    if not RESULTS.exists():
        pytest.skip("no recorded retrieval results yet")
    return json.loads(RESULTS.read_text(encoding="utf-8"))


@pytest.mark.evidence
def test_retrieval_results_match_protocol():
    rec = _load_recorded()
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert rec["protocol_sha256"] == _sha(CONFIG)
    assert rec["grid"] == cfg["grid"]
    for name, rel in rec["frozen_sources"].items():
        src = {"vector_store.py": "verifyci/contracts/vector_store.py",
               "dense.py": "verifyci/retrieval/dense.py",
               "sparse.py": "verifyci/retrieval/sparse.py",
               "fusion.py": "verifyci/retrieval/fusion.py"}[name]
        assert rel == _sha(ROOT / src), f"{name} changed since measurement"
    med1k = rec["scales"]["1000"]["dense_search"]["us"]["median"]
    med10k = rec["scales"]["10000"]["dense_search"]["us"]["median"]
    assert med10k >= med1k, "10k dense median must not beat 1k (ordering sanity)"


@pytest.mark.evidence
def test_retrieval_rerun(tmp_path):
    if os.environ.get("VERIFYCI_RETRIEVAL_RERUN") != "1":
        pytest.skip("set VERIFYCI_RETRIEVAL_RERUN=1 to re-run retrieval measurement")
    rec = _load_recorded()
    env = dict(os.environ, VERIFYCI_RETRIEVAL="1")
    subprocess.run(["python", "benchmarks/retrieval/measure.py"], check=True, env=env, cwd=ROOT)
    new = json.loads(RESULTS.read_text(encoding="utf-8"))
    assert new["protocol_sha256"] == rec["protocol_sha256"]
    assert new["grid"] == rec["grid"]
    for scale, ops in rec["scales"].items():
        for op in ("dense_search", "sparse_search"):
            old_med = ops[op]["us"]["median"]
            new_med = new["scales"][scale][op]["us"]["median"]
            assert new_med < 1.5 * old_med and new_med > 0.5 * old_med, (
                f"{scale}/{op} median drifted beyond +/-50%: {old_med} -> {new_med}")
            for tail in ("p95", "p99"):
                assert new["scales"][scale][op]["us"][tail] < 3 * ops[op]["us"][tail], (
                    f"{scale}/{op}/{tail} beyond 3x envelope")
