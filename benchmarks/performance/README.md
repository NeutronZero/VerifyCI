# Performance Benchmarks

## Overview
Provides reproducible performance benchmarking for the VerifyCI gate orchestrator across multiple workload scales (empty, small, typical multi-file, and large diffs). The harness instruments Git subprocess calls, blob reads, AST parsing, entity extraction, individual gate checks, and peak memory consumption (RSS and tracemalloc). Measurements are evaluated against frozen latency budgets with rigorous statistical confidence intervals and sample sufficiency enforcement.

## Interface
- `[measure.py:MeasurementState]`: Enumeration of valid measurement states (`MEASURED`, `NOT_MEASURED`, `INVALID`, `INSUFFICIENT_DATA`).
- `[measure.py:MEASURED]`, `[measure.py:NOT_MEASURED]`, `[measure.py:INVALID]`, `[measure.py:INSUFFICIENT_DATA]`: String constants for measurement states.
- `[measure.py:pct]`: Computes rank-based quantile / percentile from sorted numeric samples.
- `[measure.py:calc_mean_ci95]`: Calculates Student-t 95% confidence interval for sample mean.
- `[measure.py:calc_bootstrap_percentile_ci]`: Calculates non-parametric bootstrap confidence interval for arbitrary quantiles (e.g. p95).
- `[measure.py:calc_ci95]`: Backward-compatible alias for mean CI95.
- `[measure.py:summarize]`: Produces comprehensive statistical summaries (min, median, p95, p99, max, mean, stddev, confidence intervals) from raw samples.
- `[measure.py:GateProfiler]`: Context manager instrumenting Git operations, AST parsing, and check execution times during gate evaluation.
- `[measure.py:measure_parser_only]`: Isolates raw tree-sitter parsing latency on repository source files.
- `[measure.py:measure_scope_only]`: Isolates scope construction and entity extraction latency.
- `[measure.py:measure_workload_gate]`: Runs full gate benchmarks for a specified workload across cold and warm iterations with subphase attribution.
- `[measure.py:evaluate_gate]`: Evaluates measured percentiles against target limits enforcing sample sufficiency policies.
- `[measure.py:run_benchmark_suite]`: Executes all four workloads (empty, small, typical, large diffs) and compiles gate certification status.
- `[measure.py:main]`: CLI entrypoint executing benchmark suite, writing `results.json`, and printing performance reports.
- `[workloads.py:POLICY_CONTENT]`: Default `.verifyci/policy.toml` content used across synthetic repositories.
- `[workloads.py:setup_empty_diff]`: Generates a clean synthetic repository with 0 changed files between base and head.
- `[workloads.py:setup_small_diff]`: Generates a synthetic repository with a single modified source file.
- `[workloads.py:setup_typical_diff]`: Generates a multi-file synthetic repository modifying 4 cross-referencing modules.
- `[workloads.py:setup_large_diff]`: Generates a large synthetic repository modifying 52 source files deterministically.

## Invariants
- `[measure.py:evaluate_gate]` enforces an engineering sufficiency requirement (N >= 200 for p95); insufficient sample counts yield `INSUFFICIENT_DATA` rather than `MET`.
- `[measure.py:summarize]` mandates finite non-negative numbers, marking state `INVALID` on encountering NaN or negative values.
- `[measure.py:GateProfiler]` guarantees restoration of original unpatched Git methods and orchestrator check runners upon exiting its context manager.
- `[workloads.py:setup_empty_diff]` ensures identical base and head commit hashes.
- `[workloads.py:setup_large_diff]` uses a fixed random seed `20261108` to guarantee deterministic generation of 52 modified files.
- `[workloads.py:_init_repo]` forces Git configurations `core.autocrlf=false` and `core.safecrlf=false` to prevent cross-platform newline corruption.

## Side Effects
- `[measure.py:measure_workload_gate]` creates and removes temporary directory trees with scratch Git repositories and gate caches.
- `[measure.py:GateProfiler]` mutates method bindings on `GitRepo`, `scope.entities`, and `orchestrator` during the profiled run.
- `[measure.py:measure_workload_gate]` enables and resets Python memory tracing via `tracemalloc` and triggers garbage collection.
- `[measure.py:main]` writes performance benchmark results to `benchmarks/performance/results.json`.
- `[workloads.py:setup_empty_diff]`, `[workloads.py:setup_small_diff]`, `[workloads.py:setup_typical_diff]`, and `[workloads.py:setup_large_diff]` execute `git` subprocess commands and write files to disk.

## Verification
- Run: `pytest`
