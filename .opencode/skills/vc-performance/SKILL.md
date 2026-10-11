---
name: vc-performance
description: Use when benchmarking VerifyCI latency, freezing workloads, or judging performance gates
---

# VC Performance

## Overview
Frozen workloads, frozen configs, frozen protocols. p50/p95/p99 reported separately. A failed gate cannot hide behind a passing secondary metric.

## When to Use
- Latency benchmarks, threshold judgments, CAP/latency studies, perf regression checks

## Procedure
1. Freeze workload, configuration, benchmark protocol, environment. Record all four.
2. Measure with stated sample sizes; report p50, p95, p99 separately with errors and failures.
3. Judge each threshold independently: unmet threshold = FAIL even if other metrics improved.
4. Keep benchmark workloads immutable; new conditions mean new workload IDs, never edits.

## Failure handling
- Environment drift detected: invalidate the run, re-freeze.
- Threshold missed: FAIL recorded with the miss quantified; no averaging away.

## Acceptance
- Frozen protocol record, full percentile tables, per-threshold verdicts.
