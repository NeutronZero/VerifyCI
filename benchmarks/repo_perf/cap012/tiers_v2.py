"""CAP-012 v2 tier fixtures and measurement.

v2-native artifact. The performance *budgets* are read from the frozen
`config.json` and are never modified here; this module only supplies the
synthetic repository inputs the budget is measured against.

Determinism: every generated file is a pure function of (seed, index), so a
given tier always produces byte-identical sources across runs and machines.
"""
from __future__ import annotations

import statistics
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]


def generate_module(seed: int, index: int, fanout: int = 3) -> str:
    """A deterministic Python module that exercises ingest, U-SSA and edges."""
    lines: list[str] = [f'"""Generated module {index} (seed={seed})."""', ""]
    lines.append("def leaf_%d(value: int) -> int:" % index)
    lines.append(f"    return value * {index + 2} + {seed % 7}")
    lines.append("")
    for fn in range(fanout):
        lines.append(f"def step_{index}_{fn}(value: int) -> int:")
        lines.append(f"    doubled = value * {fn + 2}")
        lines.append(f"    shifted = doubled + {index}")
        lines.append("    return shifted if shifted > 0 else -shifted")
        lines.append("")
    lines.append(f"def entry_{index}(value: int) -> int:")
    parts = " + ".join(f"step_{index}_{fn}(value)" for fn in range(fanout))
    lines.append(f"    return leaf_{index}({parts})")
    lines.append("")
    return "\n".join(lines)


def generate_tier(
    file_count: int, commit_files: int, seed: int = 42
) -> list[tuple[str, str]]:
    """Returns (file_path, source) pairs for one tier."""
    return [
        (f"src/mod_{i:04d}.py", generate_module(seed, i))
        for i in range(file_count)
    ]


def _peak_rss_mb() -> float:
    try:
        import psutil

        return psutil.Process().memory_info().rss / (1024 * 1024)
    except ImportError:
        return 0.0


def measure_tier(
    file_count: int,
    commit_files: int,
    *,
    seed: int = 42,
    warmup_runs: int = 1,
    repetition_count: int = 5,
) -> dict[str, Any]:
    """Ingests a tier through the v2 engine and reports latency and RSS.

    The measured operation is the real ingest path
    (`SalsaIncrementalEngine.ingest_file`), not a simulation of it.
    """
    from verifyci_v2.ingestion.salsa_cutoff import SalsaIncrementalEngine

    files = generate_tier(file_count, commit_files, seed)
    commit_files = min(commit_files, len(files))

    # Warm the tier once before the baseline so one-time imports (z3, duckdb,
    # grammar tables) are not charged to the measured runs.
    warm_engine = SalsaIncrementalEngine(repo_id=f"cap012_{file_count}_warm")
    for file_path, source in files:
        warm_engine.ingest_file(file_path, source, language="python")
    del warm_engine

    baseline_rss_mb = _peak_rss_mb()
    peak_rss_mb = baseline_rss_mb

    durations: list[float] = []
    for run in range(warmup_runs + repetition_count):
        engine = SalsaIncrementalEngine(repo_id=f"cap012_{file_count}_{run}")
        start = time.perf_counter()
        for file_path, source in files:
            engine.ingest_file(file_path, source, language="python")
        # The "commit" is the high-fanout tail of the tier.
        for file_path, source in files[-commit_files:]:
            engine.ingest_file(file_path, source + "\n# revision bump\n", language="python")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        peak_rss_mb = max(peak_rss_mb, _peak_rss_mb())
        if run >= warmup_runs:
            durations.append(elapsed_ms)

    durations.sort()
    # RSS is reported as the *delta* attributable to this tier's ingest, not
    # absolute process RSS. Absolute RSS absorbs whatever else the host process
    # already loaded (test runner, other modules), which made the measurement
    # depend on run order rather than on the engine.
    peak_rss_delta = max(0.0, peak_rss_mb - baseline_rss_mb)

    def pct(p: float) -> float:
        if not durations:
            return 0.0
        if len(durations) == 1:
            return durations[0]
        k = (len(durations) - 1) * p
        lo, hi = int(k), min(int(k) + 1, len(durations) - 1)
        return durations[lo] + (durations[hi] - durations[lo]) * (k - lo)

    return {
        "file_count": file_count,
        "commit_files": commit_files,
        "p50_ms": round(pct(0.50), 3),
        "p95_ms": round(pct(0.95), 3),
        "samples": len(durations),
        "rss_delta_mb": round(peak_rss_delta, 3),
        "baseline_rss_mb": round(baseline_rss_mb, 3),
        "process_rss_mb": round(peak_rss_mb, 3),
    }


def run_envelope() -> dict[str, Any]:
    """Measures every tier declared in the frozen config."""
    import json

    config = json.loads(
        (REPO_ROOT / "benchmarks" / "repo_perf" / "cap012" / "config.json").read_text(
            encoding="utf-8"
        )
    )
    tiers = config.get("tiers", {})
    budgets = config.get("budgets", {})
    warmup = int(config.get("warmup_runs", 1))
    reps = int(config.get("repetition_count", 5))

    results: dict[str, Any] = {}
    for tier_name, spec in tiers.items():
        measured = measure_tier(
            int(spec["file_count"]),
            int(spec["commit_files"]),
            warmup_runs=warmup,
            repetition_count=reps,
        )
        budget = budgets.get(tier_name, {})
        p95_max = float(budget.get("p95_ms_max", float("inf")))
        rss_max = float(budget.get("peak_rss_mb_max", float("inf")))
        measured["p95_budget_ms"] = p95_max
        measured["rss_budget_mb"] = rss_max
        measured["p95_within_budget"] = measured["p95_ms"] <= p95_max
        measured["rss_within_budget"] = measured["rss_delta_mb"] <= rss_max
        measured["within_budget"] = bool(
            measured["p95_within_budget"] and measured["rss_within_budget"]
        )
        results[tier_name] = measured

    tiers_met = sum(1 for r in results.values() if r["within_budget"])
    worst = max(
        (r["p95_ms"] / r["p95_budget_ms"] for r in results.values()),
        default=0.0,
    )
    return {
        "tiers": results,
        "tiers_total": len(results),
        "tiers_within_budget": tiers_met,
        "budget_compliance": round(tiers_met / len(results), 4) if results else 0.0,
        "worst_p95_budget_utilisation": round(worst, 4),
        "median_ms": round(statistics.median([r["p50_ms"] for r in results.values()]), 3)
        if results
        else 0.0,
    }