"""CAP-012: End-to-End Repository Performance Envelope Benchmark Test Suite.

Guards:
- Declared tiers and latency/memory budgets in config.json before measurement
- Functional completion and schema verification of performance envelope
- P1-4 Reproducible gates: hard timing budget check only on pinned runner
  (skips budget gating with explicit reason when VERIFYCI_PINNED_BENCHMARK_ENV is unset)
- Isolation: temporary synthetic repos used during evaluation
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
CORPUS_DIR = REPO_ROOT / "benchmarks" / "repo_perf" / "cap012"


def test_cap012_config_tier_and_budget_declarations():
    cfg_file = CORPUS_DIR / "config.json"
    assert cfg_file.exists(), "CAP-012 config.json missing"
    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))

    assert "tiers" in cfg, "Missing tiers in config.json"
    assert "budgets" in cfg, "Missing budgets in config.json"
    assert "repetition_count" in cfg
    assert "warmup_runs" in cfg
    assert "aggregation_rule" in cfg
    assert "peak_rss_method" in cfg

    for tier_name in ("small", "medium", "large"):
        assert tier_name in cfg["tiers"], f"Tier {tier_name} missing from config"
        tier_cfg = cfg["tiers"][tier_name]
        assert "file_count" in tier_cfg
        assert "commit_files" in tier_cfg

    # Ensure budgets exist for tiers
    for tier_name in ("small", "medium", "large"):
        assert tier_name in cfg["budgets"]
        b = cfg["budgets"][tier_name]
        assert "p95_ms_max" in b
        assert "peak_rss_mb_max" in b


def test_cap012_results_schema_and_functional_completion():
    from benchmarks.repo_perf.cap012.measure_cap012 import run_cap012

    results_file = CORPUS_DIR / "results.json"
    assert results_file.exists(), "CAP-012 results.json missing"
    data = json.loads(results_file.read_text(encoding="utf-8"))

    # Provenance check
    assert "provenance" in data
    prov = data["provenance"]
    assert "git_commit" in prov
    assert "harness_sha256" in prov
    assert "config_sha256" in prov
    assert "platform" in prov

    # Functional keys in metrics
    metrics = data["metrics"]
    required_keys = {
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "peak_rss_mb",
        "storage_growth_per_rev",
        "cache_hit_rate",
        "tiers",
    }
    assert required_keys.issubset(metrics.keys())

    # Fast smoke run of run_cap012 interface
    res = run_cap012(smoke_tier_only=True)
    assert required_keys.issubset(res.keys())
    assert "small" in res["tiers"]


def test_cap012_hardware_pinned_timing_gate():
    """P1-4: Hard pass/fail timing budget gate enforced ONLY on pinned benchmark runner."""
    if not os.environ.get("VERIFYCI_PINNED_BENCHMARK_ENV"):
        pytest.skip(
            "Skipping hard latency budget gating: VERIFYCI_PINNED_BENCHMARK_ENV is not set. "
            "Timing envelope reported without fail-closed gate on unpinned host."
        )

    results_file = CORPUS_DIR / "results.json"
    data = json.loads(results_file.read_text(encoding="utf-8"))
    cfg = json.loads((CORPUS_DIR / "config.json").read_text(encoding="utf-8"))

    for tier_name, tier_metrics in data["metrics"]["tiers"].items():
        budget = cfg["budgets"][tier_name]
        assert tier_metrics["p95_ms"] <= budget["p95_ms_max"], (
            f"{tier_name} p95 {tier_metrics['p95_ms']}ms exceeds budget {budget['p95_ms_max']}ms"
        )
        assert tier_metrics["peak_rss_mb"] <= budget["peak_rss_mb_max"], (
            f"{tier_name} peak RSS {tier_metrics['peak_rss_mb']}MB exceeds budget {budget['peak_rss_mb_max']}MB"
        )
