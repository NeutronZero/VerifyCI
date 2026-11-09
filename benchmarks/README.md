# Benchmarks

## Overview
Hosts performance, latency, and scalability measurement suites for VerifyCI. The subdirectories define deterministic workloads, measurement harnesses, profiling tools, and frozen baseline classifications to monitor and guard gate execution latency, incremental parsing throughput, and temporal graph query responsiveness under strict verification contracts.

## Subdirectories & Boundaries
- [Latency](./latency/README.md) - Sub-millisecond incremental parser and temporal graph query latency measurement harnesses and profiling tools.
- [Performance](./performance/README.md) - End-to-end gate execution performance harnesses, synthetic Git workload generators, and subphase latency profilers.
