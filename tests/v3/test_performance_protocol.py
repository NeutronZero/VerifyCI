"""Tests for the new VerifyCI 3.1.11 performance measurement protocol."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.performance.measure import (
    INVALID,
    MEASURED,
    NOT_MEASURED,
    measure_parser_only,
    measure_scope_only,
    measure_workload_gate,
    summarize,
)
from benchmarks.performance.workloads import (
    setup_empty_diff,
    setup_large_diff,
    setup_small_diff,
    setup_typical_diff,
)


def test_config_structure():
    cfg_file = Path("benchmarks/performance/config.json")
    assert cfg_file.is_file()
    cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
    assert cfg["protocol"] == "verifyci-3.1.11-perf-reproducibility-v1"
    assert "budget_targets_ms" in cfg
    for w_id in ("empty_diff", "small_diff", "typical_diff", "large_diff"):
        assert w_id in cfg["budget_targets_ms"]
        assert "cold_p95" in cfg["budget_targets_ms"][w_id]
        assert "warm_p95" in cfg["budget_targets_ms"][w_id]


def test_workload_setups(tmp_path: Path):
    r_empty, b_empty, h_empty = setup_empty_diff(tmp_path)
    assert r_empty.is_dir()
    assert b_empty == h_empty

    r_small, b_small, h_small = setup_small_diff(tmp_path)
    assert b_small != h_small

    r_typ, b_typ, h_typ = setup_typical_diff(tmp_path)
    assert b_typ != h_typ

    r_lg, b_lg, h_lg = setup_large_diff(tmp_path, file_count=52)
    assert b_lg != h_lg
    py_files = list((r_lg / "src").glob("*.py"))
    assert len(py_files) >= 52


def test_summarize_statistics():
    empty_summary = summarize([])
    assert empty_summary["state"] == NOT_MEASURED

    invalid_summary = summarize([10.0, float("nan"), 20.0])
    assert invalid_summary["state"] == INVALID

    valid_vals = [float(i) for i in range(1, 101)]
    valid_summary = summarize(valid_vals)
    assert valid_summary["state"] == MEASURED
    assert valid_summary["n"] == 100
    assert valid_summary["min"] == 1.0
    assert valid_summary["max"] == 100.0
    assert valid_summary["median"] == 50.0
    assert valid_summary["p95"] == 95.0
    assert "mean_ci95" in valid_summary
    assert "p95_bootstrap_ci95" in valid_summary

    # Test confidence interval separation and containment for skewed distribution
    skewed_vals = [754.53, 917.51, 826.8, 789.04, 772.51]
    skewed_sum = summarize(skewed_vals)
    p95_val = skewed_sum["p95"]
    assert p95_val == 917.51
    # Mean CI bounds sample mean (approx 812.08), and may not cover p95
    mean_ci = skewed_sum["mean_ci95"]
    assert mean_ci[0] <= skewed_sum["mean"] <= mean_ci[1]
    # Percentile bootstrap CI bounds empirical p95
    p95_ci = skewed_sum["p95_bootstrap_ci95"]
    assert p95_ci[0] <= p95_val <= p95_ci[1]


def test_parser_and_scope_benchmarks(tmp_path: Path):
    repo, base, head = setup_small_diff(tmp_path)
    p_res = measure_parser_only(repo)
    assert p_res["state"] == MEASURED
    assert p_res["files_parsed"] >= 5
    assert p_res["cold_ms"] >= 0
    assert p_res["warm_ms"]["state"] == MEASURED

    s_res = measure_scope_only(repo, base, head)
    assert s_res["state"] == MEASURED
    assert s_res["changed_files_count"] == 1
    assert s_res["scope_construction_ms"] >= 0


def test_workload_gate_measurement(tmp_path: Path):
    res = measure_workload_gate(setup_small_diff, "small_diff_test", cold_rounds=1, warm_rounds=2)
    assert res["state"] == MEASURED
    assert res["cold_gate_ms"]["n"] == 1
    assert res["warm_gate_ms"]["n"] == 2
    sub = res["subphase_breakdown"]
    assert sub["git_subprocess_count"] >= 1
    assert sub["cold_git_subprocess_ms"] >= 0
    assert sub["cold_ast_parsing_ms"] >= 0
    assert sub["cold_entity_extraction_ms"] >= 0


def test_evaluate_gate_sample_sufficiency_enforcement():
    from benchmarks.performance.measure import evaluate_gate

    # Insufficient samples (199 < 200) cannot establish gate even when measured < target
    g_insufficient = evaluate_gate(measured_val=350.0, target_val=400.0, sample_count=199, required_samples=200)
    assert g_insufficient["status"] == "INSUFFICIENT_DATA"
    assert g_insufficient["certification_status"] == "INSUFFICIENT_DATA"
    assert g_insufficient["observed_threshold_status"] == "WITHIN_LIMIT"
    assert g_insufficient["sufficiency"] == "INSUFFICIENT"
    assert g_insufficient["threshold_passed"] is True

    # Insufficient samples where measured > target
    g_insufficient_exceed = evaluate_gate(measured_val=450.0, target_val=400.0, sample_count=199, required_samples=200)
    assert g_insufficient_exceed["status"] == "INSUFFICIENT_DATA"
    assert g_insufficient_exceed["certification_status"] == "INSUFFICIENT_DATA"
    assert g_insufficient_exceed["observed_threshold_status"] == "EXCEEDS_LIMIT"

    # Sufficient samples (200 >= 200) establish gate
    g_sufficient_met = evaluate_gate(measured_val=350.0, target_val=400.0, sample_count=200, required_samples=200)
    assert g_sufficient_met["status"] == "MET"
    assert g_sufficient_met["certification_status"] == "MET"
    assert g_sufficient_met["observed_threshold_status"] == "WITHIN_LIMIT"
    assert g_sufficient_met["sufficiency"] == "SUFFICIENT"

    g_sufficient_not_met = evaluate_gate(measured_val=450.0, target_val=400.0, sample_count=200, required_samples=200)
    assert g_sufficient_not_met["status"] == "NOT_MET"
    assert g_sufficient_not_met["certification_status"] == "NOT_MET"
    assert g_sufficient_not_met["observed_threshold_status"] == "EXCEEDS_LIMIT"
    assert g_sufficient_not_met["sufficiency"] == "SUFFICIENT"


def test_evaluate_gate_threshold_crossing():
    from benchmarks.performance.measure import evaluate_gate

    # Below limit: 599.9 <= 600.0 -> MET
    g_pass = evaluate_gate(measured_val=599.9, target_val=600.0, sample_count=250, required_samples=200)
    assert g_pass["status"] == "MET"
    assert g_pass["threshold_passed"] is True

    # Above limit: 600.1 <= 600.0 -> NOT_MET
    g_fail = evaluate_gate(measured_val=600.1, target_val=600.0, sample_count=250, required_samples=200)
    assert g_fail["status"] == "NOT_MET"
    assert g_fail["threshold_passed"] is False
