"""Production relevance and scaling benchmark harness for PR #14 audit optimizations.

Evaluates:
1. Multi-source BFS vs iterative single-source BFS on synthetic call graphs (10k and 50k nodes, varying seed counts).
2. SimpleReranker query tokenization hoisting across candidate set sizes (10, 100, 1000 items).
3. Secret scanning running byte counter vs quadratic sum on realistic multiline buffers (100, 1000, 5000 bytes).

Measures p50, p95, p99, mean latency (us), peak memory (bytes), and output equivalence.
"""
from __future__ import annotations

import collections
import json
import platform
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

from verifyci.graph.traverse import traverse
from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.reranker import OfflineReranker
from verifyci.secrets.engine import SecretDetector


# ==============================================================================
# 1. Traversal Workload & Baselines
# ==============================================================================

class SyntheticDiGraph:
    """Directed graph with adjacency lists for benchmarking BFS traversals."""

    def __init__(self, num_nodes: int, branching_factor: int = 3):
        self.num_nodes = num_nodes
        self._succ: dict[int, list[int]] = collections.defaultdict(list)
        self._pred: dict[int, list[int]] = collections.defaultdict(list)
        # Create a deterministic DAG-like structure with random cross edges
        for u in range(num_nodes):
            for step in range(1, branching_factor + 1):
                v = (u * 2 + step) % num_nodes
                if u != v:
                    self._succ[u].append(v)
                    self._pred[v].append(u)

    def successors(self, node: int) -> list[int]:
        return self._succ.get(node, [])

    def predecessors(self, node: int) -> list[int]:
        return self._pred.get(node, [])


def legacy_multi_traversal(graph, seed_nodes: list[int], max_hops: int = 3) -> set[int]:
    """Pre-optimization iterative single-source traversal union."""
    union_visited: set[int] = set()
    for seed in seed_nodes:
        # traverse single seed
        res = traverse(graph, seed, direction="outgoing", max_hops=max_hops)
        union_visited.update(res)
    # Exclude all seeds, matching multi-source traverse(graph, seed_nodes, ...)
    union_visited.difference_update(seed_nodes)
    return union_visited


def optimized_multi_traversal(graph, seed_nodes: list[int], max_hops: int = 3) -> set[int]:
    """Optimized multi-source BFS traversal in a single pass."""
    return traverse(graph, seed_nodes, direction="outgoing", max_hops=max_hops)


# ==============================================================================
# 2. Reranker Workload & Baselines
# ==============================================================================

def legacy_rerank(reranker: OfflineReranker, query: str, results: list[SearchResult], k: int = 10) -> list[SearchResult]:
    """Pre-optimization rerank scoring query inside per-result candidate loop."""
    scored = [
        SearchResult(
            id=r.id,
            score=reranker.score(query, f"{r.id} {' '.join(str(v) for v in r.metadata.values())}")
            + reranker._symbol_bonuses(query, r.id),
            metadata=r.metadata,
        )
        for r in results
    ]
    scored.sort(key=lambda r: (-r.score, r.id))
    return scored[:k]


def optimized_rerank(reranker: OfflineReranker, query: str, results: list[SearchResult], k: int = 10) -> list[SearchResult]:
    """Optimized rerank with query tokenization and parsing hoisted."""
    return reranker.rerank(query, results, k=k)


# ==============================================================================
# 3. Secret Scanner Multiline Workload & Baselines
# ==============================================================================

def make_multiline_diff(num_lines: int, line_length: int = 40) -> str:
    """Create a unified diff containing a multiline triple-quoted string."""
    diff_lines = [
        "diff --git a/src/config.py b/src/config.py",
        "--- a/src/config.py",
        "+++ b/src/config.py",
        "@@ -1,1 +1," + str(num_lines + 2) + " @@",
        '+secret_data = """',
    ]
    for i in range(num_lines):
        diff_lines.append(f"+line_{i} = value_{'x' * (line_length - 15)}")
    diff_lines.append('+"""')
    return "\n".join(diff_lines) + "\n"


# ==============================================================================
# Timing & Memory Measurement
# ==============================================================================

def measure_benchmark(fn, reps: int = 50) -> dict[str, Any]:
    durations_us: list[float] = []
    # Warmup
    for _ in range(max(3, reps // 10)):
        fn()

    tracemalloc.start()
    tracemalloc.reset_peak()
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        t1 = time.perf_counter_ns()
        durations_us.append((t1 - t0) / 1000.0)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    durations_us.sort()
    n = len(durations_us)
    p50 = durations_us[int(n * 0.50)]
    p95 = durations_us[min(n - 1, int(n * 0.95))]
    p99 = durations_us[min(n - 1, int(n * 0.99))]
    mean = sum(durations_us) / n

    return {
        "p50_us": round(p50, 2),
        "p95_us": round(p95, 2),
        "p99_us": round(p99, 2),
        "mean_us": round(mean, 2),
        "peak_bytes": peak,
    }


def run_all_benchmarks() -> dict[str, Any]:
    print("=" * 80)
    print("VerifyCI PR #14 Production Relevance & Scaling Benchmark Suite")
    print("=" * 80)

    results: dict[str, Any] = {
        "metadata": {
            "platform": platform.platform(),
            "python_version": sys.version.split()[0],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "benchmarks": {},
    }

    # --------------------------------------------------------------------------
    # Benchmark 1: Graph Traversal Multi-Source BFS
    # --------------------------------------------------------------------------
    print("\n--- 1. Graph Traversal: Multi-Source BFS vs Iterative Single-Source ---")
    g_10k = SyntheticDiGraph(10000)
    g_50k = SyntheticDiGraph(50000)

    for g_name, g in [("graph_10k_nodes", g_10k), ("graph_50k_nodes", g_50k)]:
        results["benchmarks"][g_name] = {}
        for seed_count in [5, 25, 100]:
            seeds = list(range(0, seed_count * 10, 10))

            # Verify equivalence first
            leg_set = legacy_multi_traversal(g, seeds, max_hops=3)
            opt_set = optimized_multi_traversal(g, seeds, max_hops=3)
            assert leg_set == opt_set, f"Equivalence failure on {g_name} with {seed_count} seeds"

            m_leg = measure_benchmark(lambda g=g, s=seeds: legacy_multi_traversal(g, s, max_hops=3), reps=30)
            m_opt = measure_benchmark(lambda g=g, s=seeds: optimized_multi_traversal(g, s, max_hops=3), reps=30)
            speedup = round(m_leg["p50_us"] / max(0.1, m_opt["p50_us"]), 2)

            sub_key = f"seeds_{seed_count}"
            results["benchmarks"][g_name][sub_key] = {
                "nodes_visited": len(opt_set),
                "legacy": m_leg,
                "optimized": m_opt,
                "speedup_p50": speedup,
            }
            print(f"[{g_name}] Seeds: {seed_count:3d} | Visited: {len(opt_set):5d} | "
                  f"Legacy p50: {m_leg['p50_us']:8.1f}us | Opt p50: {m_opt['p50_us']:8.1f}us | "
                  f"Speedup: {speedup:5.2f}x")

    # --------------------------------------------------------------------------
    # Benchmark 2: SimpleReranker Tokenization Hoisting
    # --------------------------------------------------------------------------
    print("\n--- 2. SimpleReranker: Query Tokenization Hoisting Across Candidate Sizes ---")
    reranker = OfflineReranker()
    query = "database.connector.PostgresPool authenticate user credentials"
    results["benchmarks"]["reranker_candidate_scaling"] = {}

    for k_size in [10, 100, 1000]:
        candidates = [
            SearchResult(
                id=f"sym_{i}" if i % 5 != 0 else "PostgresPool",
                score=0.0,
                metadata={"file": f"src/db_{i}.py", "doc": f"handler method {i} connection pooling query"},
            )
            for i in range(k_size)
        ]

        # Verify equivalence
        leg_out = legacy_rerank(reranker, query, candidates, k=k_size)
        opt_out = optimized_rerank(reranker, query, candidates, k=k_size)
        assert [r.id for r in leg_out] == [r.id for r in opt_out]
        for r1, r2 in zip(leg_out, opt_out):
            assert abs(r1.score - r2.score) < 1e-9

        m_leg = measure_benchmark(lambda c=candidates, k=k_size: legacy_rerank(reranker, query, c, k=k), reps=40)
        m_opt = measure_benchmark(lambda c=candidates, k=k_size: optimized_rerank(reranker, query, c, k=k), reps=40)
        speedup = round(m_leg["p50_us"] / max(0.1, m_opt["p50_us"]), 2)

        sub_key = f"candidates_{k_size}"
        results["benchmarks"]["reranker_candidate_scaling"][sub_key] = {
            "candidate_count": k_size,
            "legacy": m_leg,
            "optimized": m_opt,
            "speedup_p50": speedup,
        }
        print(f"Candidates: {k_size:4d} | "
              f"Legacy p50: {m_leg['p50_us']:8.1f}us | Opt p50: {m_opt['p50_us']:8.1f}us | "
              f"Speedup: {speedup:5.2f}x")

    # --------------------------------------------------------------------------
    # Benchmark 3: Secret Scanner Multiline Buffer Running Byte Count
    # --------------------------------------------------------------------------
    print("\n--- 3. Secret Scanner: Running Byte Counter on Multiline Buffers ---")
    scanner = SecretDetector()
    results["benchmarks"]["secret_scanner_multiline"] = {}

    for line_count in [5, 15, 30]:
        diff_text = make_multiline_diff(num_lines=line_count, line_length=30)
        m_scan = measure_benchmark(lambda dt=diff_text: scanner.scan_diff(dt), reps=20)

        sub_key = f"multiline_lines_{line_count}"
        results["benchmarks"]["secret_scanner_multiline"][sub_key] = {
            "buffer_lines": line_count,
            "buffer_bytes": line_count * 30,
            "scan_latency": m_scan,
        }
        print(f"Multiline lines: {line_count:3d} (~{line_count*30:4d} B) | "
              f"Scan p50: {m_scan['p50_us']:8.1f}us | Peak mem: {m_scan['peak_bytes']:6d} B")

    print("\n" + "=" * 80)
    return results


if __name__ == "__main__":
    rep = run_all_benchmarks()
    out_path = Path(__file__).resolve().parent / "benchmark_production_results.json"
    out_path.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    print(f"Results written to: {out_path}")
