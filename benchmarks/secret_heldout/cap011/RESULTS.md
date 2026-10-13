# CAP-011 Benchmark Results: Held-Out Secret Detection & Redaction Safety

## 1. Cryptographic Freeze Coordinates
- **Experiment ID**: CAP-011
- **Corpus SHA-256**: `8dcb519d55df0a1828a70d0c857606be40f81551239dbe8d34cdf808b01dbe52`
- **Labels SHA-256**: `5dbdf268508b62f071c65942bbb262ba969a695a99e4c08471ad35d9d49b0307`
- **Total Cases**: 50 (30 positive, 20 negative)
- **Provenance Commit**: `bd57eb0f1cafe1b4e6d623732dcd3df4d22debc2` (dirty: False)

## 2. Gates Table with Predeclared Thresholds

| Gate | Predeclared Threshold | Measured Value | Classification |
|---|---|---|---|
| Overall Detection Recall | >= 0.95 | 1.0 | Measured-Met, Not Established |
| Name-Independent Recall | >= 0.90 | 1.0 | Measured-Met, Not Established |
| Precision (Held-Out) | >= 0.99 | 1.0 | Measured-Met, Not Established |
| Redaction Violations (Runtime) | = 0 | 0 | Measured-Met, Not Established |
| False Acceptance Rate (FAR) | <= 0.01 | 0.0 | Measured-Met, Not Established |
| False Rejection Rate (FRR) | <= 0.05 | 0.0 | Measured-Met, Not Established |


## 3. Per-Slice Breakdown

- **connection_strings**: Recall 1.0, Precision 1.0 (5 cases)
- **encoded**: Recall 1.0, Precision 1.0 (5 cases)
- **name_independent**: Recall 1.0, Precision 1.0 (10 cases)
- **negatives_placeholders**: Recall 1.0, Precision 1.0 (10 cases)
- **negatives_test_fixtures**: Recall 1.0, Precision 1.0 (10 cases)
- **private_keys**: Recall 1.0, Precision 1.0 (5 cases)
- **provider_structured**: Recall 1.0, Precision 1.0 (5 cases)

## 4. Decisive Results & P0-3 Redaction Analysis
- **P0-3 Redaction Boundary**: Zero raw synthetic secret leakage into runtime artifacts (`results.json`, `RESULTS.md`).
- **Name-Independent Recall**: Neutral variables (`x`, `temp`, `target`) successfully detected without keyword context.
- **Negative Rejection**: Zero false positives on documentation placeholders (`YOUR_API_KEY_HERE`), UUIDs, and git commit hashes.
