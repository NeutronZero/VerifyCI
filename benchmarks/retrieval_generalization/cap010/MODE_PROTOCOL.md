# CAP-010 Protocol: Retrieval Generalization (FROZEN)

**Experiment ID**: CAP-010  
**Corpus SHA-256**: `32e792ac3e8978549bf9bde53dd18c1aa142ea867f4881601b6a0ec548d2fc20`  
**Label SHA-256**: `431c0909626cb728a0174ba59a0716d180421218c700ce9ef9eab3caf2f7f8e6`  
**Total Queries**: 210 (6 categories, 35 each)  
**Total Documents**: 1050 across 12 repos (8 dev, 4 held-out)  

## Invariants
1. **P0-2 No-Answer Scoring**: No-relevant-result queries have ideal DCG 0; strictly excluded from nDCG mean and evaluated via abstention metrics.
2. **True Cross-Repo Generalization**: Evaluated across both 8 development repos and 4 held-out repos as answer-bearing targets.
3. **Dense + Sparse Hybrid Ranking**: Evaluates hybrid dense+BM25 with RRF fusion.
