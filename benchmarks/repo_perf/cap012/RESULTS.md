# CAP-012 Benchmark Results: Repository Performance Envelope

## 1. Cryptographic Coordinates & Hardware Context
- **Experiment ID**: CAP-012
- **Provenance Commit**: `9684c795613ad8c4c501c7c752e92da98029f9fe` (dirty: False)
- **Platform**: `Windows-11-10.0.26300-SP0`
- **Processor**: `Intel64 Family 6 Model 140 Stepping 1, GenuineIntel`
- **Python**: `3.14.4`
- **Peak RSS Method**: `psutil_process_rss`

## 2. Predeclared Budgets vs. Measured Performance Table

| Tier | Budget p95 Max | Measured p95 | Budget Peak RSS Max | Measured Peak RSS |
|---|---|---|---|---|
| `small` | 250.0 ms | 128.97 ms (MET) | 100.0 MB | 45.58 MB (MET) |
| `medium` | 1000.0 ms | 244.8 ms (MET) | 250.0 MB | 52.16 MB (MET) |
| `large` | 5000.0 ms | 2159.14 ms (MET) | 500.0 MB | 75.73 MB (MET) |

## 3. Evidence Classification
- **Functional Completion & Schema**: Measured-Met, Not Established
- **Small Tier Timing**: Measured-Met, Not Established (gated only under `VERIFYCI_PINNED_BENCHMARK_ENV`)
- **Medium Tier Timing**: Measured-Met, Not Established
- **Large Tier Timing**: Measured-Met, Not Established
- **Overall System Envelope**: Measured-Met, Not Established

## 4. Hardware Envelope Invariants (P1-4)
- Timing distributions across Windows and Linux are strictly maintained without cross-platform mixing.
- Repositories were synthesized in isolated temporary filesystems with clean disposal.
