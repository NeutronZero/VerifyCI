# Benchmarks

## Overview
Hosts performance, latency, and scalability measurement suites for VerifyCI. The subdirectories define deterministic workloads, measurement harnesses, profiling tools, and frozen baseline classifications to monitor and guard gate execution latency, incremental parsing throughput, and temporal graph query responsiveness under strict verification contracts.

## Subdirectories & Boundaries
- [Latency](./latency/README.md) - **Retired (v1).** Targets the removed `verifyci.ingestion.*` API and cannot run against v3.1. Retained unmodified as frozen historical evidence; new latency work belongs in `performance/`.
- [Performance](./performance/README.md) - End-to-end gate execution performance harnesses, synthetic Git workload generators, and subphase latency profilers.

Frozen baselines and oracles are never rewritten to accommodate a code change (see [STABILITY.md](../STABILITY.md)).
