# CAP-009 Benchmark Results: End-to-End Diff-to-Impact Correctness

## 1. Cryptographic Freeze Coordinates
- **Experiment ID**: CAP-009
- **Corpus SHA-256**: `a9f76b89c9f114590c04d7d2e2ee3714504d13ad7d9ff075df505d9d81048ea6`
- **Labels SHA-256**: `5081fa37d3bfff1a67562900b2c54560dde688de60708feb77d883ab3b281d99`
- **Total Cases**: 225
- **Provenance Commit**: `bd57eb0f1cafe1b4e6d623732dcd3df4d22debc2` (dirty: False)

## 2. Gates Table with Predeclared Thresholds

| Gate | Predeclared Threshold | Measured Value | Classification |
|---|---|---|---|
| Critical Adversarial False Passes | = 0 | 0 | Measured-Met, Not Established |
| Representative Seed Precision | >= 0.95 | 1.0 | Measured-Met, Not Established |
| Representative Seed Recall | >= 0.95 | 1.0 | Measured-Met, Not Established |
| Representative Impact Precision | >= 0.95 | 1.0 | Measured-Met, Not Established |
| Representative Impact Recall | >= 0.95 | 1.0 | Measured-Met, Not Established |
| Latency p95 | <= 50.0 ms | 0.0656 ms | Measured-Met, Not Established |


## 3. Per-Slice Breakdown
- Pure Insertions: 25/25 verified
- Deletions: 25/25 verified
- Multi-Hunk: 25/25 verified
- Renames: 25/25 verified
- Nested Scopes: 25/25 verified
- Decorators: 25/25 verified
- Same-Basename Collisions: 25/25 verified (0 collision false positives)
- Mixed Language: 25/25 verified
- Adversarial Critical: 25/25 verified (0 false passes)

## 4. Decisive Results & Falsifier Analysis
- Same-basename collision protection verified: changes to `auth/client.py` do not falsely seed `api/client.py`.
- Renamed source diffs resolve to new paths without dropping AST entities.
- Clean-room oracle verified independent of production `diffmap`.
