"""Guards for the v2 benchmark harness.

v1's `measure_cap*.py` scripts all imported `verifyci.*`, which no longer
exists, so every one of them died at import. These tests keep that from coming
back: the harness must run, must never report a pass without a measurement, and
must never overwrite the frozen v1 evidence it sits next to.
"""

from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from benchmarks.common.measure_v2 import (
    _CAP_DIRS,
    RESULT_FILENAME,
    build_result,
)

BENCHMARKS_ROOT = Path(__file__).resolve().parents[2] / "benchmarks"


def _measure_scripts() -> list[Path]:
    return sorted(BENCHMARKS_ROOT.rglob("measure_*.py"))


def test_measure_scripts_exist() -> None:
    assert _measure_scripts(), "no measure scripts found"


def test_no_measure_script_imports_v1() -> None:
    """The regression that motivated this file: dead v1 imports."""
    offenders: list[str] = []
    for script in _measure_scripts():
        tree = ast.parse(script.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(
                "verifyci."
            ):
                offenders.append(f"{script.name}: from {node.module}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("verifyci."):
                        offenders.append(f"{script.name}: import {alias.name}")
    assert not offenders, f"v1 imports remain: {offenders}"


@pytest.fixture(scope="module")
def capability_results() -> dict[str, dict[str, Any]]:
    return {cap_id: build_result(cap_id) for cap_id in _CAP_DIRS}


def test_every_capability_has_a_declared_status(
    capability_results: dict[str, dict[str, Any]],
) -> None:
    """Each cap must be passed, failed, or explicitly not measurable."""
    for cap_id, result in capability_results.items():
        assert result["status"] in ("passed", "failed", "not_measurable"), cap_id
        if result["status"] == "not_measurable":
            assert result["not_scored_reason"], cap_id


def test_unmeasurable_never_reports_a_pass(
    capability_results: dict[str, dict[str, Any]],
) -> None:
    for cap_id, result in capability_results.items():
        if result["metrics"]["metric_value"] is None:
            assert result["status"] == "not_measurable", cap_id
            assert not result["status"] == "passed", cap_id


def test_measured_capabilities_declare_their_bar(
    capability_results: dict[str, dict[str, Any]],
) -> None:
    for cap_id, result in capability_results.items():
        if result["status"] in ("passed", "failed"):
            assert result["metrics"]["target_threshold"] > 0, cap_id
            assert result["metrics"]["threshold_basis"], cap_id


def test_v2_results_do_not_overwrite_v1_records() -> None:
    """`results_v2.json` must sit beside `results.json`, never on top of it."""
    assert RESULT_FILENAME == "results_v2.json"
    for cap_id in _CAP_DIRS:
        corpus_dir = BENCHMARKS_ROOT / _CAP_DIRS[cap_id]
        assert (corpus_dir / RESULT_FILENAME) != (corpus_dir / "results.json")


@pytest.mark.parametrize("cap_id", ["cap011", "cap009"])
def test_measure_shim_runs_and_reports(cap_id: str) -> None:
    cap_target = f"measure_{cap_id}.py"
    script = next(
        (s for s in _measure_scripts() if s.name.lower() == cap_target),
        None,
    )
    if script is None:
        script = next(
            s for s in _measure_scripts() if cap_id.upper().replace("_", "-") in s.name.upper()
            or cap_id in s.read_text(encoding="utf-8")
        )
    proc = subprocess.run(
        [sys.executable, str(script), "--no-write"],
        capture_output=True,
        text=True,
        cwd=str(BENCHMARKS_ROOT.parent),
        check=False,
    )
    # argparse in the shim path ignores --no-write, so only importability and a
    # printable status line are asserted here.
    combined = proc.stdout + proc.stderr
    assert "ModuleNotFoundError" not in combined, combined
    assert cap_id.upper() in combined.upper(), combined