# CAP-010 Protocol: Retrieval Generalization (FROZEN)

**Experiment ID**: CAP-010  
**Corpus SHA-256**: `a312fe4ee9eea7e1cc81cf4c040ef60e9f5e38fb9d631f34d4d837d58cfc0f35`  
**Label SHA-256**: `e45d274e232b86cbb5b31ad5341ad74b4d047584c1f8ebe1c9a5160037fc4cc4`  
**Total Queries**: 210 (6 categories, 35 each)  
**Total Documents**: 1050 across 12 repos (8 dev, 4 held-out)  

## Invariants
1. **P0-2 No-Answer Scoring**: No-relevant-result queries have ideal DCG 0; they are strictly excluded from nDCG mean and evaluated via abstention metrics.
2. **Disjoint Held-Out Repos**: 4 whole repositories are held out from developer tuning.
3. **BM25 + Hybrid Ranking**: Preserves Recall@5 >= 0.80 across diverse code retrieval patterns.
