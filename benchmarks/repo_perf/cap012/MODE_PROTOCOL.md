# CAP-012 Protocol: Repository Performance Envelope (FROZEN)

**Experiment ID**: CAP-012  
**Workload Tiers**: small (10 files / 1-file diff), medium (50 files / 10-file diff), large (200 files / 50-file diff)  
**Order**: Warmup (1 run) -> Small -> Medium -> Large, with cache isolation between tiers.

## Hardware & Environment Invariants (P1-4)
1. **Runner Pinned Gating**: Hard pass/fail latency gates apply ONLY when running on the designated pinned environment (`VERIFYCI_PINNED_BENCHMARK_ENV=1`).
2. **OS Isolation**: Latency distributions between Windows and Linux runners are strictly separated and never merged.
3. **No Workspace Dirtying**: Repositories are synthesized in temporary directories and cleanly discarded.
4. **End-to-End Metric Capture**:
   - `p50_ms`, `p95_ms`, `p99_ms` across repeated trials (median aggregation)
   - `peak_rss_mb` via process tracemalloc
   - `storage_growth_per_rev` (database size delta per revision)
   - `cache_hit_rate` (warm vs cold execution efficiency)
