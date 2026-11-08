"""Tests verifying that verifyci has zero heavyweight dependencies in core verification and imports fast."""

from __future__ import annotations

import subprocess
import sys
import pytest

_PROHIBITED_MODULES = [
    "torch",
    "sentence_transformers",
    "duckdb",
    "llguidance",
    "fastmcp",
]


def test_core_does_not_import_heavy_dependencies() -> None:
    """Verify that importing verifyci and verifyci.cli does not pull in heavy native libraries."""
    code = (
        "import sys\n"
        "import verifyci\n"
        "import verifyci.cli\n"
        "import verifyci.gate.orchestrator\n"
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

    assert proc.returncode == 0, f"Prohibited modules imported: {proc.stdout}"


@pytest.mark.performance
def test_cli_import_latency_under_40ms() -> None:
    """Measure fresh process import latency of verifyci.cli."""
    code = (
        "import time\n"
        "t0 = time.perf_counter()\n"
        "import verifyci.cli\n"
        "t1 = time.perf_counter()\n"
        "print(f'{(t1 - t0)*1000:.2f}')\n"
    )

    durations: list[float] = []
    for _ in range(5):
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        durations.append(float(proc.stdout.strip()))

    best_ms = min(durations)
    print(f"verifyci.cli best import latency: {best_ms:.2f} ms (runs: {durations})")
    assert best_ms < 40.0, f"Import latency regression: {best_ms:.2f} ms >= 40.0 ms"
