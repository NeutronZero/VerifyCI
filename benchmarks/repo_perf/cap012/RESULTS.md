# CAP-012 Benchmark Results: Repository Performance Envelope

## 1. Cryptographic Coordinates & Hardware Context
- **Experiment ID**: CAP-012
- **Provenance Commit**: `f32b640164e63d777fb2300c142d54d5ab0c00f0` (dirty: True)
- **Platform**: `Windows-11-10.0.26300-SP0`
- **Processor**: `Intel64 Family 6 Model 140 Stepping 1, GenuineIntel`
- **Python**: `3.14.7`
- **Peak RSS Method**: `tracemalloc_process_peak`

## 2. Predeclared Budgets vs. Measured Performance Table

| Tier | Budget p95 Max | Measured p95 | Budget Peak RSS Max | Measured Peak RSS |
|---|---|---|---|---|
| `small` | 250.0 ms | 242.14 ms (MET) | 100.0 MB | 0.33 MB (MET) |
| `medium` | 1000.0 ms | 408.56 ms (MET) | 250.0 MB | 1.0 MB (MET) |
| `large` | 5000.0 ms | 1399.1 ms (MET) | 500.0 MB | 4.13 MB (MET) |

## 3. Evidence Classification
- **Functional Completion & Schema**: Established
- **Small Tier Timing**: Measured-Met, Not Established (gated only under `VERIFYCI_PINNED_BENCHMARK_ENV`)
- **Medium Tier Timing**: Measured-Met, Not Established
- **Large Tier Timing**: Measured-Met, Not Established
- **Overall System Envelope**: Measured-Met, Not Established

## 4. Hardware Envelope Invariants (P1-4)
- Timing distributions across Windows and Linux are strictly maintained without cross-platform mixing.
- Repositories were synthesized in isolated temporary filesystems with clean disposal.
