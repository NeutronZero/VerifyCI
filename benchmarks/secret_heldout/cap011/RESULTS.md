# CAP-011 Benchmark Results: Held-Out Secret Detection & Redaction Safety

## 1. Cryptographic Freeze Coordinates
- **Experiment ID**: CAP-011
- **Corpus SHA-256**: `72865e81db5bbd975ec8cb1710940b5203347ca39f12334a26c7cc339bd0c57f`
- **Labels SHA-256**: `9e3bbc98a9ca549f981db3f25d280663c42d2c855e556e29ae6569da2d8572b7`
- **Total Cases**: 50 (30 positive, 20 negative)
- **Provenance Commit**: `ad2da60210861fb4cc6feeb047e864543d41b1f8` (dirty: True)

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
