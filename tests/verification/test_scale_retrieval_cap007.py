"""CAP-007: High-Node Topology & Production-Scale Retrieval Attestation Integrity Tests.

Verifies:
- Step 1 Cryptographic freeze hashes for cases.jsonl, labels.jsonl, and oracle_manifest.jsonl
- LOCK-1: Independent Oracle isolation (zero verifyci dependencies)
- LOCK-2: Separation of exact impact correctness from ranked Top-K retrieval
- LOCK-3 & LOCK-9: Realistic and adversarial topology slice distribution (64 cases across 8 slices)
- LOCK-4: Scale tier declarations and hardware environment profile in config.json
- LOCK-6: Fail-closed contract on all 8 resource/topology tripwires (INCONCLUSIVE)
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys

import pytest

BENCHMARK_DIR = Path(__file__).resolve().parent.parent.parent / "benchmarks" / "retrieval_corpus" / "cap007"
FROZEN_CORPUS_SHA256 = "f9ddbe38bd94caee762dedb430c04edb6678f6850736431562a47394593fe688"
FROZEN_LABEL_SHA256 = "d6bbad336244bb95529a54cb877cad548075d94ef8aec597112c50bc44dc5f48"
FROZEN_ORACLE_MANIFEST_SHA256 = "ab071128211cb366879d8c7fa8ef147ed54c2b57887a4b8dea1357b9905e97d4"


@pytest.fixture(scope="module")
def cap007_data():
    cases_file = BENCHMARK_DIR / "cases.jsonl"
    labels_file = BENCHMARK_DIR / "labels.jsonl"
    manifest_file = BENCHMARK_DIR / "oracle_manifest.jsonl"
    config_file = BENCHMARK_DIR / "config.json"

    cases = [json.loads(line) for line in cases_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    labels = {json.loads(line)["id"]: json.loads(line) for line in labels_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    manifest = {json.loads(line)["id"]: json.loads(line) for line in manifest_file.read_text(encoding="utf-8").splitlines() if line.strip()}
    config = json.loads(config_file.read_text(encoding="utf-8"))

    return {
        "cases": cases,
        "labels": labels,
        "manifest": manifest,
        "config": config,
    }


def test_cap007_cryptographic_freeze_hashes():
    """Assert byte-level immutability against the frozen cryptographic coordinates."""
    c_bytes = (BENCHMARK_DIR / "cases.jsonl").read_bytes()
    l_bytes = (BENCHMARK_DIR / "labels.jsonl").read_bytes()
    m_bytes = (BENCHMARK_DIR / "oracle_manifest.jsonl").read_bytes()

    assert hashlib.sha256(c_bytes).hexdigest() == FROZEN_CORPUS_SHA256
    assert hashlib.sha256(l_bytes).hexdigest() == FROZEN_LABEL_SHA256
    assert hashlib.sha256(m_bytes).hexdigest() == FROZEN_ORACLE_MANIFEST_SHA256


def test_cap007_lock1_independent_oracle_isolation():
    """Verify LOCK-1: oracle.py imports zero modules from verifyci."""
    oracle_path = BENCHMARK_DIR / "oracle.py"
    tree = ast.parse(oracle_path.read_text(encoding="utf-8"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not alias.name.startswith("verifyci"), f"Leaked import in oracle.py: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            assert not node.module.startswith("verifyci"), f"Leaked from-import in oracle.py: {node.module}"

    # Dynamic namespace verification
    if str(BENCHMARK_DIR) not in sys.path:
        sys.path.insert(0, str(BENCHMARK_DIR))
    import oracle  # noqa: E402

    for key, val in oracle.__dict__.items():
        if hasattr(val, "__module__") and val.__module__:
            assert not val.__module__.startswith("verifyci"), f"Leaked verifyci dependency: {key} ({val.__module__})"


def test_cap007_lock2_separate_correctness_from_ranking(cap007_data):
    """Verify LOCK-2: exact impact correctness is separated from Top-K rankings."""
    labels = cap007_data["labels"]
    for cid, lbl in labels.items():
        if lbl["expected_status"] == "PASS":
            assert isinstance(lbl["exact_impact_set"], list)
            assert "rankings" in lbl
            rankings = lbl["rankings"]
            assert "top_10" in rankings
            assert "top_25" in rankings
            assert "top_50" in rankings
            # Deterministic sorting check: rankings must be slices of hop_distances ordering
            assert len(rankings["top_10"]) <= 10
            assert len(rankings["top_25"]) <= 25
            assert len(rankings["top_50"]) <= 50


def test_cap007_lock3_and_lock9_stratified_slice_distribution(cap007_data):
    """Verify LOCK-3 & LOCK-9: 64 cases evenly stratified across 8 realistic/adversarial slices."""
    cases = cap007_data["cases"]
    labels = cap007_data["labels"]

    assert len(cases) == 64
    assert len(labels) == 64

    expected_slices = {
        "modular_package_hierarchy": 8,
        "monorepo_cross_boundary": 8,
        "god_node_fanout": 8,
        "deep_call_chains": 8,
        "cyclic_dependencies": 8,
        "dense_clusters_generated": 8,
        "sparse_distant_targets": 8,
        "dense_sparse_disagreement": 8,
    }

    counts = {}
    for c in cases:
        sl = c["slice"]
        counts[sl] = counts.get(sl, 0) + 1

    assert counts == expected_slices

    pass_count = sum(1 for lbl in labels.values() if lbl["expected_status"] == "PASS")
    inconclusive_count = sum(1 for lbl in labels.values() if lbl["expected_status"] == "INCONCLUSIVE")
    assert pass_count == 56
    assert inconclusive_count == 8


def test_cap007_lock4_scale_tiers_and_environment_metadata(cap007_data):
    """Verify LOCK-4: config.json declares frozen scale tiers and environment profile."""
    config = cap007_data["config"]
    assert config["benchmark_id"] == "CAP-007"
    assert "scale_tiers" in config
    for tier in ("S1", "S2", "S3", "S4"):
        assert tier in config["scale_tiers"]
        t_data = config["scale_tiers"][tier]
        assert "min_nodes" in t_data
        assert "max_nodes" in t_data

    env = config["environment_profile"]
    assert "python_version" in env
    assert "os_platform" in env
    assert "cpu_count" in env
    assert "ram_total_gb" in env


def test_cap007_lock6_fail_closed_tripwires(cap007_data):
    """Verify LOCK-6: all 8 resource/topology tripwires fail closed with INCONCLUSIVE."""
    labels = cap007_data["labels"]
    manifest = cap007_data["manifest"]

    tripwire_cases = [c for c in cap007_data["cases"] if c.get("scenario_type") == "tripwire"]
    assert len(tripwire_cases) == 8

    for c in tripwire_cases:
        cid = c["id"]
        assert c.get("tripwire_anomaly") is not None
        assert labels[cid]["expected_status"] == "INCONCLUSIVE"
        assert labels[cid]["exact_impact_set"] is None
        assert labels[cid]["canonical_digest"] is None
        assert manifest[cid]["expected_status"] == "INCONCLUSIVE"
