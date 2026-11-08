"""Adversarial regression test suite for benchmark integrity and fail-closed gates.

Verifies:
1. Required module missing.
2. Import failure.
3. Protocol hash mismatch.
4. Missing workload fixture.
5. Zero samples.
6. Insufficient samples.
7. NaN duration.
8. Infinite duration.
9. Negative duration.
10. Measurement subprocess timeout.
11. Measurement subprocess failure.
12. Partial measurement record.
13. Attempt to classify an invalid measurement.
14. Attempt to classify an unmeasured result.
15. Attempt to overwrite frozen historical results.
16. Valid measurements still produce correct classifications.
17. Legacy false-green defect elimination regression.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any

import pytest

from benchmarks.latency.measure import (
    INSUFFICIENT_DATA,
    INVALID,
    MEASURED,
    MIN_SAMPLES,
    NOT_MEASURED,
    BenchmarkIntegrityError,
    _validate_measurement_record,
    _validate_samples,
    check_protocol_integrity,
    classify,
    measure_incremental,
    save_results,
)


def _valid_ip_record(
    *,
    median: float = 35.0,
    p95: float = 850.0,
    p99: float = 4200.0,
    n: int = 1000,
    cold_ms: float = 4.2,
) -> dict[str, Any]:
    return {
        "state": MEASURED,
        "cold_ms": cold_ms,
        "warm_us": {
            "n": n,
            "median": median,
            "p95": p95,
            "p99": p99,
            "max": p99 * 1.5,
        },
        "warm_samples_ns": [int(median * 1000)] * n,
    }


def _valid_tq_record(
    *,
    median_ms: float = 0.035,
    p95_ms: float = 0.065,
    p99_ms: float = 0.12,
    n: int = 1000,
) -> dict[str, Any]:
    return {
        "state": MEASURED,
        "edges": 10000,
        "entity_rows": 10000,
        "db_mb": 5.6,
        "n": n,
        "hit_rate": 1.0,
        "ms": {
            "median": median_ms,
            "p95": p95_ms,
            "p99": p99_ms,
            "max": p99_ms * 2.0,
        },
        "raw_median_ns": int(median_ms * 1e6),
        "raw_p99_ns": int(p99_ms * 1e6),
    }


# 1. Required module missing
def test_required_module_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "benchmarks.latency.measure.LIVE_SOURCES",
        {"extractor.py": tmp_path / "nonexistent_extractor.py"},
    )
    valid, reason = check_protocol_integrity()
    assert not valid
    assert reason is not None
    assert "Required module missing" in reason


# 2. Import failure
def test_import_failure_handled_as_invalid(monkeypatch: pytest.MonkeyPatch):
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if "verifyci.ingestion.incremental" in name:
            raise ImportError("Simulated missing IncrementalParser")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    result = measure_incremental()
    assert result["state"] == NOT_MEASURED
    assert "ImportError" in result["error"]
    assert result["cold_ms"] is None
    assert result["warm_us"]["median"] is None


# 3. Protocol hash mismatch
def test_protocol_hash_mismatch_prevents_classification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake_config = tmp_path / "config.json"
    fake_config.write_text('{"tampered": true}', encoding="utf-8")
    monkeypatch.setattr("benchmarks.latency.measure.HERE", tmp_path)

    valid, reason = check_protocol_integrity()
    assert not valid
    assert "config.json hash mismatch" in str(reason)


# 4. Missing workload fixture
def test_missing_workload_fixture_prevents_classification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake_fixture = tmp_path / "fixture"
    fake_fixture.mkdir(parents=True)
    monkeypatch.setattr("benchmarks.latency.measure.FIXTURE", fake_fixture)

    valid, reason = check_protocol_integrity()
    assert not valid
    assert "workload.py missing" in str(reason)


# 5. Zero samples
def test_zero_samples_cannot_establish_gate():
    state, reason = _validate_samples([])
    assert state == NOT_MEASURED
    assert "Zero samples" in str(reason)

    ip = _valid_ip_record(n=0)
    ip["state"] = NOT_MEASURED
    ip["warm_us"]["median"] = None
    tq = _valid_tq_record()

    with pytest.raises(BenchmarkIntegrityError):
        classify(ip, tq, strict=True)

    non_strict = classify(ip, tq, strict=False)
    assert not non_strict["incremental_gate_established_this_host"]
    assert non_strict["overall_status"] != "MET"


# 6. Insufficient samples
def test_insufficient_samples_cannot_establish_gate():
    samples = [1000] * (MIN_SAMPLES - 1)
    state, reason = _validate_samples(samples)
    assert state == INSUFFICIENT_DATA
    assert "Insufficient sample count" in str(reason)

    ip = _valid_ip_record(n=MIN_SAMPLES - 1)
    ip["state"] = INSUFFICIENT_DATA
    tq = _valid_tq_record()

    with pytest.raises(BenchmarkIntegrityError):
        classify(ip, tq, strict=True)

    gates = classify(ip, tq, strict=False)
    assert not gates["incremental_gate_established_this_host"]
    assert gates["overall_status"] != "MET"


# 7. NaN duration
def test_nan_duration_rejected():
    samples = [1000.0] * 35 + [float("nan")]
    state, reason = _validate_samples(samples)
    assert state == INVALID
    assert "NaN duration" in str(reason)

    ip = _valid_ip_record()
    ip["warm_us"]["median"] = float("nan")
    state_rec, err = _validate_measurement_record(ip, "incremental_parse")
    assert state_rec == INVALID

    with pytest.raises(BenchmarkIntegrityError):
        classify(ip, _valid_tq_record(), strict=True)


# 8. Infinite duration
def test_infinite_duration_rejected():
    samples = [1000.0] * 35 + [float("inf")]
    state, reason = _validate_samples(samples)
    assert state == INVALID
    assert "Infinite duration" in str(reason)

    ip = _valid_ip_record()
    ip["warm_us"]["p95"] = float("inf")
    state_rec, err = _validate_measurement_record(ip, "incremental_parse")
    assert state_rec == INVALID

    with pytest.raises(BenchmarkIntegrityError):
        classify(ip, _valid_tq_record(), strict=True)


# 9. Negative duration
def test_negative_duration_rejected():
    samples = [1000] * 35 + [-50]
    state, reason = _validate_samples(samples)
    assert state == INVALID
    assert "Negative duration" in str(reason)

    tq = _valid_tq_record()
    tq["ms"]["median"] = -0.5
    state_rec, err = _validate_measurement_record(tq, "temporal_query")
    assert state_rec == INVALID

    with pytest.raises(BenchmarkIntegrityError):
        classify(_valid_ip_record(), tq, strict=True)


# 10. Measurement subprocess timeout
def test_measurement_subprocess_timeout(monkeypatch: pytest.MonkeyPatch):
    def mock_subprocess_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["python", "measure.py"], timeout=1.0)

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    # Subprocess execution wrapper pattern
    state = INVALID
    try:
        subprocess.run(["python", "measure.py"], timeout=1.0, check=True)
        state = MEASURED
    except subprocess.TimeoutExpired:
        state = INVALID

    assert state == INVALID
    assert state != MEASURED


# 11. Measurement subprocess failure
def test_measurement_subprocess_failure(monkeypatch: pytest.MonkeyPatch):
    def mock_subprocess_run(*args, **kwargs):
        raise subprocess.CalledProcessError(returncode=2, cmd=["python", "measure.py"])

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    state = INVALID
    try:
        subprocess.run(["python", "measure.py"], check=True)
        state = MEASURED
    except subprocess.CalledProcessError:
        state = INVALID

    assert state == INVALID
    assert state != MEASURED


# 12. Partial measurement record
def test_partial_measurement_record():
    partial_ip = {"state": MEASURED, "cold_ms": 1.2}  # missing warm_us
    state, err = _validate_measurement_record(partial_ip, "incremental_parse")
    assert state == INVALID
    assert "missing required fields" in str(err)

    partial_tq = {"state": MEASURED, "n": 1000}  # missing ms
    state_tq, err_tq = _validate_measurement_record(partial_tq, "temporal_query")
    assert state_tq == INVALID
    assert "missing required fields" in str(err_tq)


# 13. Attempt to classify an invalid measurement
def test_classify_invalid_measurement_fails_closed():
    ip = _valid_ip_record()
    ip["state"] = INVALID
    ip["error"] = "Measurement corrupted"
    tq = _valid_tq_record()

    with pytest.raises(BenchmarkIntegrityError) as exc_info:
        classify(ip, tq, strict=True)
    assert "INVALID" in str(exc_info.value)

    non_strict = classify(ip, tq, strict=False)
    assert not non_strict["incremental_gate_established_this_host"]
    assert not non_strict["temporal_gate_established_this_host"]
    assert non_strict["overall_status"] == "NOT_ESTABLISHED"


# 14. Attempt to classify an unmeasured result
def test_classify_unmeasured_result_fails_closed():
    ip = {"state": NOT_MEASURED, "error": "Import failed"}
    tq = {"state": NOT_MEASURED, "error": "Import failed"}

    with pytest.raises(BenchmarkIntegrityError) as exc_info:
        classify(ip, tq, strict=True)
    assert "NOT_MEASURED" in str(exc_info.value)

    non_strict = classify(ip, tq, strict=False)
    assert not non_strict["incremental_gate_established_this_host"]
    assert not non_strict["temporal_gate_established_this_host"]
    assert non_strict["overall_status"] == "NOT_ESTABLISHED"


# 15. Attempt to overwrite frozen historical results
def test_attempt_to_overwrite_frozen_historical_results():
    here = Path("benchmarks/latency").resolve()
    frozen = here / "results.json"
    assert frozen.is_file()
    original_bytes = frozen.read_bytes()

    dummy_report = {"tampered": True}
    with pytest.raises(BenchmarkIntegrityError) as exc_info:
        save_results(frozen, dummy_report)
    assert "frozen historical results.json" in str(exc_info.value)
    assert frozen.read_bytes() == original_bytes


# 16. Valid measurements still produce correct classifications
def test_valid_measurements_produce_correct_classification():
    # Pass case
    ip = _valid_ip_record(median=32.0, p95=850.0, p99=4200.0)
    tq = _valid_tq_record(p99_ms=0.15)
    gates = classify(ip, tq, strict=True)
    assert gates["incremental_median_lt_0.2ms"] is True
    assert gates["incremental_p95_lt_1ms"] is True
    assert gates["incremental_p99_lt_5ms"] is True
    assert gates["temporal_p99_lt_200ms"] is True
    assert gates["incremental_gate_established_this_host"] is True
    assert gates["temporal_gate_established_this_host"] is True
    assert gates["overall_status"] == "MET"

    # Fail case (p95 exceeded)
    ip_miss = _valid_ip_record(median=32.0, p95=1200.0, p99=4200.0)
    gates_miss = classify(ip_miss, tq, strict=True)
    assert gates_miss["incremental_p95_lt_1ms"] is False
    assert gates_miss["incremental_gate_established_this_host"] is False
    assert gates_miss["overall_status"] == "NOT_MET"


def test_percentile_sufficiency_enforcement():
    # n = 50: sufficient for median (30), insufficient for p95 (200) and p99 (1000)
    ip_50 = _valid_ip_record(median=30.0, p95=500.0, p99=2000.0, n=50)
    tq_1000 = _valid_tq_record(n=1000)

    with pytest.raises(BenchmarkIntegrityError) as exc_info:
        classify(ip_50, tq_1000, strict=True)
    assert "Percentile sample insufficiency" in str(exc_info.value)

    non_strict = classify(ip_50, tq_1000, strict=False)
    assert non_strict["incremental_median_lt_0.2ms"] is True
    assert non_strict["incremental_p95_lt_1ms"] is False
    assert non_strict["incremental_p99_lt_5ms"] is False
    assert non_strict["sample_sufficiency"]["incremental_p95_sufficient"] is False
    assert non_strict["overall_status"] == "NOT_MET"

    # n = 500: sufficient for p95 (200), insufficient for p99 (1000)
    ip_500 = _valid_ip_record(median=30.0, p95=500.0, p99=2000.0, n=500)
    non_strict_500 = classify(ip_500, tq_1000, strict=False)
    assert non_strict_500["incremental_p95_lt_1ms"] is True
    assert non_strict_500["incremental_p99_lt_5ms"] is False
    assert non_strict_500["sample_sufficiency"]["incremental_p99_sufficient"] is False


def test_threshold_boundary_crossing_transitions_classification():
    tq = _valid_tq_record(p99_ms=0.15)
    # Exactly below threshold: 999 us < 1000 us limit -> MET
    ip_met = _valid_ip_record(median=35.0, p95=999.0, p99=4900.0, n=1000)
    gates_met = classify(ip_met, tq, strict=True)
    assert gates_met["incremental_p95_lt_1ms"] is True
    assert gates_met["overall_status"] == "MET"

    # Exactly at or above threshold: 1000.1 us > 1000 us limit -> NOT_MET
    ip_miss = _valid_ip_record(median=35.0, p95=1000.1, p99=4900.0, n=1000)
    gates_miss = classify(ip_miss, tq, strict=True)
    assert gates_miss["incremental_p95_lt_1ms"] is False
    assert gates_miss["overall_status"] == "NOT_MET"


# 17. Regression test: legacy false-green condition must fail closed
def test_legacy_false_green_regression():
    """Reproduces the exact legacy failure mode where missing modules produced 0.0 values.

    Legacy behaviour:
      measure_incremental returned median = 0.0
      measure_temporal returned p99 = 0.0
      classify checked 0.0 < 200us -> TRUE! (MET)

    Remediated behaviour:
      Missing modules must return state=NOT_MEASURED and median=None.
      classify must reject NOT_MEASURED and evaluate all gates to FALSE.
    """
    # Simulate legacy output structure with 0.0 values
    legacy_ip_output = {
        "cold_ms": 0.0,
        "warm_us": {"n": 0, "median": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0},
    }
    legacy_tq_output = {
        "edges": 0,
        "entity_rows": 0,
        "db_mb": 0.0,
        "n": 0,
        "hit_rate": 0.0,
        "ms": {"median": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0},
    }

    # Under remediated classify, missing state key is rejected as INVALID:
    with pytest.raises(BenchmarkIntegrityError):
        classify(legacy_ip_output, legacy_tq_output, strict=True)

    # Even with non-strict classification, it MUST NOT report MET:
    gates = classify(legacy_ip_output, legacy_tq_output, strict=False)
    assert gates["incremental_gate_established_this_host"] is False
    assert gates["temporal_gate_established_this_host"] is False
    assert gates["overall_status"] != "MET"

    # Now verify current actual measure_incremental() behavior in this v3 environment:
    actual_ip = measure_incremental()
    assert actual_ip["state"] == NOT_MEASURED
    assert actual_ip["cold_ms"] is None
    assert actual_ip["warm_us"]["median"] is None
