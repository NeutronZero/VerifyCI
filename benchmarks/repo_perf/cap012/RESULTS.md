# CAP-012 Benchmark Results: Repository Performance Envelope

## 1. Cryptographic Coordinates & Hardware Context
- **Experiment ID**: CAP-012
- **Provenance Commit**: `becb9a01c30a6e3f8cfb9f5336ba6d57e9fa1806` (dirty: False)
- **Platform**: `Windows-11-10.0.26300-SP0`
- **Processor**: `Intel64 Family 6 Model 140 Stepping 1, GenuineIntel`
- **Python**: `3.14.4`
- **Peak RSS Method**: `psutil_process_rss`

## 2. Predeclared Budgets vs. Measured Performance Table

| Tier | Budget p95 Max | Measured p95 | Budget Peak RSS Max | Measured Peak RSS |
|---|---|---|---|---|
| `small` | 250.0 ms | 111.64 ms (MET) | 100.0 MB | 44.43 MB (MET) |
| `medium` | 1000.0 ms | 236.67 ms (MET) | 250.0 MB | 49.09 MB (MET) |
| `large` | 5000.0 ms | 1125.72 ms (MET) | 500.0 MB | 63.48 MB (MET) |

## 3. Evidence Classification
- **Functional Completion & Schema**: Measured-Met, Not Established
- **Small Tier Timing**: Measured-Met, Not Established (gated only under `VERIFYCI_PINNED_BENCHMARK_ENV`)
- **Medium Tier Timing**: Measured-Met, Not Established
- **Large Tier Timing**: Measured-Met, Not Established
- **Overall System Envelope**: Measured-Met, Not Established

## 4. Hardware Envelope Invariants (P1-4)
- Timing distributions across Windows and Linux are strictly maintained without cross-platform mixing.
- Repositories were synthesized in isolated temporary filesystems with clean disposal.
