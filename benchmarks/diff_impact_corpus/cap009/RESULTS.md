# CAP-009 Benchmark Results: End-to-End Diff-to-Impact Correctness

## 1. Cryptographic Freeze Coordinates
- **Experiment ID**: CAP-009
- **Corpus SHA-256**: `f588414156bd2eedbedbf94f5b7451cb1fa1939b05710a270cd72c7de74b7580`
- **Labels SHA-256**: `6e6d2e5e3f74bf2e7e2a664782ca62eccbb1efd9f0be51f5ec4e9922e24aa774`
- **Total Cases**: 225
- **Provenance Commit**: `f5ef360f4b9df6e26590e4ceb9959ac7b7b31c53` (dirty: False)

## 2. Gates Table with Predeclared Thresholds

| Gate | Predeclared Threshold | Measured Value | Classification |
|---|---|---|---|
| Critical Adversarial False Passes | = 0 | 0 | Established |
| Representative Seed Precision | >= 0.95 | 1.0 | Established |
| Representative Seed Recall | >= 0.95 | 1.0 | Established |
| Representative Impact Precision | >= 0.95 | 1.0 | Established |
| Representative Impact Recall | >= 0.95 | 1.0 | Established |
| Latency p95 | <= 50.0 ms | 0.051 ms | Measured-Met, Not Established |


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
