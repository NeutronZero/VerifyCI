# CAP-010 Benchmark Results: Retrieval Generalization & Hard Negatives

## 1. Cryptographic Freeze Coordinates
- **Experiment ID**: CAP-010
- **Corpus SHA-256**: `62161689b4478475d4ec5a43f08f19f5214c1762a9e0c6d1e9ca0b85319dce31`
- **Labels SHA-256**: `ea461629678dff8be90069fd8b3cf6b9ebec0937b23a6efb85054effb33c1a4e`
- **Total Queries**: 210
- **Total Documents**: 1050 across 12 repositories
- **Provenance Commit**: `5bab3b2e163b9c0bb246de90bb12808394f6e5cd` (dirty: False)

## 2. Gates Table with Predeclared Thresholds

| Gate | Predeclared Threshold | Measured Value | Classification |
|---|---|---|---|
| Overall Recall@5 | >= 0.80 | 0.8629 | Measured-Met, Not Established |
| Overall Recall@20 | >= 0.90 | 0.9771 | Measured-Met, Not Established |
| Overall nDCG@10 (Excluding No-Answer) | >= 0.50 | 0.6883 | Measured-Met, Not Established |
| Correct Abstention Rate (No-Answer Slice) | >= 0.90 | 1.0 | Measured-Met, Not Established |
| False Relevant Rate (No-Answer Slice) | <= 0.10 | 0.0 | Measured-Met, Not Established |


## 3. Per-Category Breakdown (With Wilson Score 95% Confidence Intervals)

- **exact_symbol**: Recall@5 1.0 (Bootstrap Mean 95% CI: [1.0, 1.0], Hit-Rate Wilson 95% CI: [0.9011, 1.0]), nDCG@10 0.931
- **misleading_lexical**: Recall@5 0.6857 (Bootstrap Mean 95% CI: [0.5143, 0.8], Hit-Rate Wilson 95% CI: [0.5202, 0.8145]), nDCG@10 0.4599
- **multi_hop**: Recall@5 0.7143 (Bootstrap Mean 95% CI: [0.6429, 0.8], Hit-Rate Wilson 95% CI: [0.9011, 1.0]), nDCG@10 0.5383
- **no_relevant_result**: Abstention 1.0 (Wilson 95% CI: [0.9011, 1.0])
- **paraphrase**: Recall@5 0.9143 (Bootstrap Mean 95% CI: [0.8, 1.0], Hit-Rate Wilson 95% CI: [0.7762, 0.9704]), nDCG@10 0.6212
- **rare_identifier**: Recall@5 1.0 (Bootstrap Mean 95% CI: [1.0, 1.0], Hit-Rate Wilson 95% CI: [0.9011, 1.0]), nDCG@10 0.8908

- **Cross-Repo Split**: Dev Recall@5 = 0.8348, Held-Out Recall@5 = 0.9167

## 4. Evidence Classification Taxonomy
- **Status**: Measured-Met, Not Established
- **Rationale**: Demonstrates hybrid dense+BM25 retrieval on synthetic multi-repository corpus, but population-wide generalization requires broad real-world corpus.

## 5. Decisive Results & P0-2 Falsifier Analysis
- **P0-2 No-Answer Scoring**: No-relevant-result queries strictly excluded from nDCG and evaluated via abstention.
- **Genuine Cross-Repo Generalization**: Evaluated on 4 held-out repositories (`held_out_repo_09` to `held_out_repo_12`) with active query targets.
