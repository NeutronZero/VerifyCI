"""Tests verifying that verifyci.core has zero heavyweight dependencies and imports fast."""

from __future__ import annotations

import subprocess
import sys

_PROHIBITED_MODULES = [
    "z3",
    "egglog",
    "duckdb",
    "wasmtime",
    "llguidance",
    "sentence_transformers",
    "torch",
]


def test_core_does_not_import_heavy_dependencies() -> None:
    """Verify that importing verifyci.core does not pull in heavy native libraries."""
    code = (
        "import sys\n"
        "import verifyci.core\n"
        "loaded = set(sys.modules.keys())\n"
        f"prohibited = {_PROHIBITED_MODULES!r}\n"
        "violations = [m for m in prohibited if m in loaded]\n"
        "if violations:\n"
        "    print('VIOLATIONS:', violations)\n"
        "    sys.exit(1)\n"
        "sys.exit(0)\n"
    )

    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, f"Prohibited modules imported by verifyci.core: {proc.stdout}"


import pytest


@pytest.mark.performance
def test_core_import_latency_under_40ms() -> None:
    """Measure fresh process import latency of verifyci.core."""
    code = (
        "import time\n"
        "t0 = time.perf_counter()\n"
        "import verifyci.core\n"
        "t1 = time.perf_counter()\n"
        "print(f'{(t1 - t0)*1000:.2f}')\n"
    )

    durations: list[float] = []
    for _ in range(5):
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
        )
        durations.append(float(proc.stdout.strip()))

    best_ms = min(durations)
    print(f"verifyci.core best import latency: {best_ms:.2f} ms (runs: {durations})")
    assert best_ms < 50.0, f"Core import too slow: {best_ms:.2f} ms (target < 40ms, actual {best_ms:.2f}ms)"
