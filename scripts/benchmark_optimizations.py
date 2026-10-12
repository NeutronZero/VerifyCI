"""Reproducible benchmark harness comparing baseline vs optimized implementations
for VerifyCI.

Measures:
- Latency percentiles: p50, p95, p99 (microseconds or milliseconds)
- Peak memory usage and allocation metrics (tracemalloc)
- Both representative and stress workloads (large repos, collisions, dense spans)
Outputs a structured summary table and JSON result report.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import json
import os
import platform
import subprocess
import time
import tracemalloc
from types import MappingProxyType
from typing import Any

from verifyci.contracts.jsonio import to_json_dict
from verifyci.storage.graph_cache import _freeze_payload
from verifyci.verification.diffmap import (
    map_files_to_entity_ids,
    normalize_path,
)
from verifyci.verification.verification_ir import (
    _anchor_covered,
    _merge_spans,
)


# ==============================================================================
# Baseline Reference Implementations (Pre-optimization)
# ==============================================================================

def map_files_to_entity_ids_baseline(files: list[str], entities: list) -> dict[str, list[str]]:
    wanted = {normalize_path(f) for f in files}
    mapping: dict[str, list[str]] = {}
    for entity in entities:
        epath = normalize_path(getattr(entity, "file_path", ""))
        for f in wanted:
            if epath == f or epath.endswith("/" + f) or f.endswith("/" + epath):
                mapping.setdefault(f, []).append(entity.revision_entity_id)
    return mapping


def anchor_covered_baseline(ln: int, file_spans: list[tuple[int, int]], content: str = "") -> bool:
    if any(s <= ln <= en for s, en in file_spans):
        return True
    if content.lstrip().startswith("@"):
        return any(s - ln == 1 for s, en in file_spans)
    if content.lstrip().startswith(("import ", "from ")):
        return any(abs(s - ln) <= 2 or abs(en - ln) <= 2 for s, en in file_spans)
    return False


def to_json_dict_baseline(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_json_dict_baseline(getattr(obj, f.name)) for f in fields(obj)}
    from collections.abc import Mapping
    if isinstance(obj, (Mapping, dict)):
        return {k: to_json_dict_baseline(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_json_dict_baseline(v) for v in obj]
    return obj


def freeze_payload_baseline(val: Any) -> Any:
    """Pre-optimization freeze allocating fresh collections on every call."""
    if val is None or isinstance(val, (int, float, str, bool, bytes)):
        return val
    from collections.abc import Mapping
    if isinstance(val, (Mapping, dict)):
        return MappingProxyType({k: freeze_payload_baseline(v) for k, v in val.items()})
    if isinstance(val, (list, tuple)):
        return tuple(freeze_payload_baseline(x) for x in val)
    if isinstance(val, (set, frozenset)):
        return frozenset(freeze_payload_baseline(x) for x in val)
    return val


# ==============================================================================
# Benchmarking Utilities
# ==============================================================================

def measure_latencies(fn, reps: int = 100) -> dict[str, float]:
    """Measure execution times and return p50, p95, p99, mean in microseconds."""
    durations_us: list[float] = []
    # Warmup
    for _ in range(max(5, reps // 10)):
        fn()

    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        t1 = time.perf_counter_ns()
        durations_us.append((t1 - t0) / 1000.0)

    durations_us.sort()
    n = len(durations_us)
    p50 = durations_us[int(n * 0.50)]
    p95 = durations_us[min(n - 1, int(n * 0.95))]
    p99 = durations_us[min(n - 1, int(n * 0.99))]
    mean_val = sum(durations_us) / n
    return {
        "p50_us": round(p50, 2),
        "p95_us": round(p95, 2),
        "p99_us": round(p99, 2),
        "mean_us": round(mean_val, 2),
    }


def measure_memory(fn, reps: int = 50) -> dict[str, int]:
    """Measure peak memory and allocation deltas in bytes."""
    tracemalloc.start()
    tracemalloc.reset_peak()
    for _ in range(reps):
        fn()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "peak_bytes": peak,
        "current_bytes": current,
    }


# ==============================================================================
# Workload Definitions
# ==============================================================================

@dataclass
class SimpleEntity:
    revision_entity_id: str
    file_path: str


class StatusEnum(Enum):
    PENDING = "pending"
    VERIFIED = "verified"


@dataclass
class ComplexRecord:
    status: StatusEnum
    count: int
    score: float
    is_active: bool
    tags: list[str]
    props: dict[str, Any]


def run_all_benchmarks() -> dict[str, Any]:
    results = {}

    # --------------------------------------------------------------------------
    # Benchmark 1: Diff Entity Mapping
    # --------------------------------------------------------------------------
    print("Running Benchmark 1: Diff Entity Mapping...")

    # Workload 1A: Large Repository (10,000 entities across 500 files, 10 changed files)
    all_files = [f"src/module_{i}/service_{j}.py" for i in range(25) for j in range(20)]
    entities_large = [
        SimpleEntity(revision_entity_id=f"e_{i}", file_path=all_files[i % len(all_files)])
        for i in range(10_000)
    ]
    query_files_10 = all_files[:10]

    lat_b1_base = measure_latencies(lambda: map_files_to_entity_ids_baseline(query_files_10, entities_large), reps=50)
    lat_b1_opt = measure_latencies(lambda: map_files_to_entity_ids(query_files_10, entities_large), reps=50)
    mem_b1_base = measure_memory(lambda: map_files_to_entity_ids_baseline(query_files_10, entities_large), reps=20)
    mem_b1_opt = measure_memory(lambda: map_files_to_entity_ids(query_files_10, entities_large), reps=20)

    # Workload 1B: Basename Collision Stress (50 files with same basename 'handler.py')
    collision_files = [f"services/pkg_{i}/handler.py" for i in range(50)]
    entities_collisions = [
        SimpleEntity(revision_entity_id=f"e_{i}", file_path=collision_files[i % len(collision_files)])
        for i in range(5_000)
    ]
    query_collisions = collision_files[:5]

    lat_b1_col_base = measure_latencies(lambda: map_files_to_entity_ids_baseline(query_collisions, entities_collisions), reps=50)
    lat_b1_col_opt = measure_latencies(lambda: map_files_to_entity_ids(query_collisions, entities_collisions), reps=50)

    results["diff_mapping"] = {
        "large_repo_10k_entities": {
            "baseline": lat_b1_base,
            "optimized": lat_b1_opt,
            "speedup_p50": round(lat_b1_base["p50_us"] / max(0.1, lat_b1_opt["p50_us"]), 2),
            "baseline_peak_bytes": mem_b1_base["peak_bytes"],
            "optimized_peak_bytes": mem_b1_opt["peak_bytes"],
        },
        "basename_collisions_5k_entities": {
            "baseline": lat_b1_col_base,
            "optimized": lat_b1_col_opt,
            "speedup_p50": round(lat_b1_col_base["p50_us"] / max(0.1, lat_b1_col_opt["p50_us"]), 2),
        },
    }

    # --------------------------------------------------------------------------
    # Benchmark 2: Graph Cache Freezing
    # --------------------------------------------------------------------------
    print("Running Benchmark 2: Graph Cache Freezing...")
    deep_graph_payload = (
        ("node_1", {"id": "1", "meta": {"kind": "func", "tags": ("a", "b", "c")}}),
        ("node_2", {"id": "2", "meta": {"kind": "class", "tags": ("d", "e")}}),
        ("edge_1", {"type": "CALLS", "weight": 1.0}),
    ) * 50

    # First freeze to get already-frozen structure
    frozen_payload = _freeze_payload(deep_graph_payload)

    lat_b2_base = measure_latencies(lambda: freeze_payload_baseline(frozen_payload), reps=200)
    lat_b2_opt = measure_latencies(lambda: _freeze_payload(frozen_payload), reps=200)
    mem_b2_base = measure_memory(lambda: freeze_payload_baseline(frozen_payload), reps=100)
    mem_b2_opt = measure_memory(lambda: _freeze_payload(frozen_payload), reps=100)

    results["graph_cache_freezing"] = {
        "repeated_freeze_already_frozen": {
            "baseline": lat_b2_base,
            "optimized": lat_b2_opt,
            "speedup_p50": round(lat_b2_base["p50_us"] / max(0.1, lat_b2_opt["p50_us"]), 2),
            "baseline_peak_bytes": mem_b2_base["peak_bytes"],
            "optimized_peak_bytes": mem_b2_opt["peak_bytes"],
            "memory_reduction_ratio": round(mem_b2_base["peak_bytes"] / max(1, mem_b2_opt["peak_bytes"]), 2),
        }
    }

    # --------------------------------------------------------------------------
    # Benchmark 3: IR Line Attribution Interval Containment
    # --------------------------------------------------------------------------
    print("Running Benchmark 3: IR Line Attribution...")
    # 500 dense nested and overlapping spans across 50,000 lines
    spans = [(i * 100, i * 100 + 80) for i in range(500)]
    merged = _merge_spans(spans)
    starts = [s for s, _ in merged]
    dec_starts = {s - 1 for s, _ in spans}
    endpoints = sorted({s for s, _ in spans} | {en for _, en in spans})

    # Test queries distributed across the file
    query_lines = [i * 95 + 10 for i in range(200)]

    def run_ir_baseline():
        for ln in query_lines:
            anchor_covered_baseline(ln, spans, "x = 1")

    def run_ir_optimized():
        for ln in query_lines:
            _anchor_covered(ln, merged, starts, "x = 1", dec_starts, endpoints)

    lat_b3_base = measure_latencies(run_ir_baseline, reps=100)
    lat_b3_opt = measure_latencies(run_ir_optimized, reps=100)
    mem_b3_base = measure_memory(run_ir_baseline, reps=50)
    mem_b3_opt = measure_memory(run_ir_optimized, reps=50)

    results["ir_line_attribution"] = {
        "dense_spans_500_intervals": {
            "baseline": lat_b3_base,
            "optimized": lat_b3_opt,
            "speedup_p50": round(lat_b3_base["p50_us"] / max(0.1, lat_b3_opt["p50_us"]), 2),
            "baseline_peak_bytes": mem_b3_base["peak_bytes"],
            "optimized_peak_bytes": mem_b3_opt["peak_bytes"],
        }
    }

    # --------------------------------------------------------------------------
    # Benchmark 4: JSON Serialization Fast-Path
    # --------------------------------------------------------------------------
    print("Running Benchmark 4: JSON Serialization...")
    sample_records = [
        ComplexRecord(
            status=StatusEnum.VERIFIED if i % 2 == 0 else StatusEnum.PENDING,
            count=i,
            score=0.95 + (i % 5) * 0.01,
            is_active=(i % 3 != 0),
            tags=[f"tag_{i}", "code", "verified"],
            props={"nested_int": i * 10, "nested_bool": True, "raw_str": f"val_{i}"},
        )
        for i in range(100)
    ]

    lat_b4_base = measure_latencies(lambda: [to_json_dict_baseline(r) for r in sample_records], reps=100)
    lat_b4_opt = measure_latencies(lambda: [to_json_dict(r) for r in sample_records], reps=100)

    results["json_serialization"] = {
        "complex_records_100_items": {
            "baseline": lat_b4_base,
            "optimized": lat_b4_opt,
            "speedup_p50": round(lat_b4_base["p50_us"] / max(0.1, lat_b4_opt["p50_us"]), 2),
        }
    }

    # Environment & Metadata
    git_rev = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    env_info = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "git_commit": git_rev,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    full_report = {
        "environment": env_info,
        "benchmarks": results,
    }
    return full_report


if __name__ == "__main__":
    report = run_all_benchmarks()
    out_path = "scripts/benchmark_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[OK] Benchmarks complete. Results saved to {out_path}\n")
    print(json.dumps(report, indent=2))
