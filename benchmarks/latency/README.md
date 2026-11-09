# Latency Benchmarks

## Overview
Provides reproducible latency benchmarking and profiling harnesses for VerifyCI incremental parsing and temporal graph query operations. The suite validates sub-millisecond AST re-parsing via tree-sitter on modified buffers and sub-second temporal queries (`get_entity_as_of`) at scale (10,000 edges). Protocol parameters and source integrity hashes are frozen to guarantee repeatable local host characterization without altering baseline artifacts.

## Interface
- `[measure.py:BenchmarkIntegrityError]`: Exception raised when benchmark inputs, protocol files, or measurements fail integrity invariants.
- `[measure.py:MeasurementState]`: Enumeration of valid measurement states (`MEASURED`, `NOT_MEASURED`, `INVALID`, `INSUFFICIENT_DATA`).
- `[measure.py:MEASURED]`, `[measure.py:NOT_MEASURED]`, `[measure.py:INVALID]`, `[measure.py:INSUFFICIENT_DATA]`, `[measure.py:VALID_STATES]`: String constants and frozenset of valid measurement states.
- `[measure.py:check_protocol_integrity]`: Verifies `config.json`, workload fixtures, and referenced live source modules against frozen SHA256 digests.
- `[measure.py:env_block]`: Collects host hardware and runtime environment metadata (Python version, platform, CPU count, memory).
- `[measure.py:pct]`: Computes rank-based quantile / percentile from sorted sequences.
- `[measure.py:measure_incremental]`: Evaluates cold full-parse baseline and warm incremental reparse latencies over edited tree-sitter buffers.
- `[measure.py:build_scale_db]`: Deterministically generates a temporary 10,000-edge temporal graph store across 5 revision versions.
- `[measure.py:measure_temporal]`: Evaluates temporal point-in-time entity query latencies (`get_entity_as_of`) at 10,000 edges.
- `[measure.py:classify]`: Evaluates incremental parse and temporal query measurements against performance thresholds with sample sufficiency checks.
- `[measure.py:save_results]`: Persists benchmark results to a target JSON file while guarding the frozen baseline.
- `[measure.py:measure]`: Executes the complete latency benchmark harness with protocol verification, incremental parsing, and temporal query timings.
- `[measure.py:main]`: CLI entrypoint for latency measurement with formatted console reporting and fail-closed exit codes.
- `[h3_measure.py:H3A]`, `[h3_measure.py:V102]`: Baseline reference timing dictionaries for H3-A reproduction and v1.0.2 baselines.
- `[h3_measure.py:main]`: Executes H3 latency verification and writes `results_h3.json`.
- `[h3_profile.py:per_line_spread]`: Measures per-line parse latency distribution across interior code line edits.
- `[h3_profile.py:wrapper_cost]`: Quantifies tree-sitter wrapper lookup overhead versus full parse latency.
- `[h3_profile.py:main]`: CLI entrypoint printing per-line latency spread and wrapper overhead diagnostics.

## Invariants
- `[measure.py:check_protocol_integrity]` requires exact cryptographic SHA256 parity for `config.json`, `fixture/workload.py`, and core modules (`extractor.py`, `graph_store.py`, `intent_align.py`, `provider.py`, `env.py`).
- `[measure.py:measure]` fails immediately with `SystemExit` if `VERIFYCI_LATENCY=1` is not explicitly set in the execution environment.
- `[measure.py:save_results]` strictly forbids overwriting the frozen `benchmarks/latency/results.json` baseline file, raising `BenchmarkIntegrityError`.
- `[measure.py:classify]` enforces fail-closed semantics: non-`MEASURED` states or insufficient sample counts (N < 30 for median, N < 200 for p95, N < 1000 for p99) cannot establish a passing gate.
- `[measure.py:build_scale_db]` guarantees deterministic graph construction with exact counts of 10,000 edges and 10,000 entity rows using fixed seed `20261003`.
- `[h3_measure.py:main]` asserts `incremental_median_lt_0.2ms` and `temporal_p99_lt_200ms` gate compliance and halts if `results_h3.json` exists unless `VERIFYCI_REBENCHMARK=1`.
- `[h3_profile.py:per_line_spread]` executes `[measure.py:_preflight_shape]` to guarantee incremental parse AST equivalency to cold parse before collecting measurements.

## Side Effects
- `[measure.py:measure_temporal]` and `[measure.py:build_scale_db]` create and remove temporary directory trees containing SQLite database files (`scale10k.db`).
- `[measure.py:measure_incremental]`, `[measure.py:measure_temporal]`, and `[h3_profile.py:per_line_spread]` explicitly disable and re-enable Python garbage collection (`gc.disable()`, `gc.enable()`).
- `[measure.py:save_results]` writes benchmark JSON records to specified filesystem destinations.
- `[h3_measure.py:main]` writes campaign benchmark output to `benchmarks/latency/results_h3.json`.
- `[measure.py:main]`, `[h3_measure.py:main]`, and `[h3_profile.py:main]` write diagnostic and metric summaries to standard output and standard error.

## Verification
- Run: `pytest`
