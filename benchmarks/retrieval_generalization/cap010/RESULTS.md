# CAP-010 Benchmark Results: Retrieval Generalization & Hard Negatives

## 1. Cryptographic Freeze Coordinates
- **Experiment ID**: CAP-010
- **Corpus SHA-256**: `a312fe4ee9eea7e1cc81cf4c040ef60e9f5e38fb9d631f34d4d837d58cfc0f35`
- **Labels SHA-256**: `e45d274e232b86cbb5b31ad5341ad74b4d047584c1f8ebe1c9a5160037fc4cc4`
- **Total Queries**: 210
- **Total Documents**: 1050 across 12 repositories
- **Provenance Commit**: `f32b640164e63d777fb2300c142d54d5ab0c00f0` (dirty: True)

## 2. Gates Table with Predeclared Thresholds

| Gate | Predeclared Threshold | Measured Value | Classification |
|---|---|---|---|
| Overall Recall@5 | >= 0.80 | 0.8286 | Established |
| Overall Recall@20 | >= 0.90 | 0.9143 | Established |
| Overall nDCG@10 (Excluding No-Answer) | >= 0.50 | 0.7908 | Established |
| Correct Abstention Rate (No-Answer Slice) | >= 0.90 | 1.0 | Established |
| False Relevant Rate (No-Answer Slice) | <= 0.10 | 0.0 | Established |


## 3. Per-Category Breakdown (With 95% Confidence Intervals)

- **exact_symbol**: Recall@5 1.0 (CI: [1.0, 1.0]), nDCG@10 1.0
- **misleading_lexical**: Recall@5 1.0 (CI: [1.0, 1.0]), nDCG@10 0.8786
- **multi_hop**: Recall@5 1.0 (CI: [1.0, 1.0]), nDCG@10 0.9455
- **no_relevant_result**: Abstention 1.0 (35 queries)
- **paraphrase**: Recall@5 0.1429 (CI: [0.0252, 0.2605]), nDCG@10 0.1298
- **rare_identifier**: Recall@5 1.0 (CI: [1.0, 1.0]), nDCG@10 1.0

## 4. Decisive Results & P0-2 Falsifier Analysis
- **P0-2 No-Answer Scoring**: No-relevant-result queries have undefined ideal DCG; they are strictly excluded from nDCG and evaluated by clean abstention.
- **Cross-Repo Generalization**: Evaluated on 4 fully held-out repositories (`held_out_repo_09` to `held_out_repo_12`) with zero leakage into development or tuning.
- **Hard Negatives**: Misleading lexical overlap cases successfully separated via ranking disambiguation.
