# CAP-001 dense/rerank experiment (PRE-COMMITTED)

## Q1 hypothesis
RRF fuses ranks but never re-scores content: pairs where dense and BM25
disagree are ordered by rank arithmetic, not by query-doc relevance.
A cross-encoder (MS-MARCO-trained pairwise scorer) re-scores the hybrid
top-20 and should fix inversions RRF cannot, raising hybrid nDCG while
frozen dense stays fixed. MiniLM bi-encoder arm tests whether the dense
floor itself is model-bound.

## Arms (same corpus/queries/qrels/scoring/tiebreak as frozen gate)
- D0 frozen nomic dense (reference 0.6220; recomputed, not trusted)
- D1 MiniLM dense (sentence-transformers/all-MiniLM-L6-v2, local only)
- H0 frozen hybrid (equal-weight RRF k=60, reference 0.6603; recomputed)
- H1 H0 top-20 + cross-encoder rerank to top-10 (ms-marco-MiniLM-L-6-v2)
- H2 MiniLM dense + BM25 RRF + rerank top-20 to top-10

No sweeping: rerank depth 20 fixed a priori (2x scoring k; standard).
No weights touched (equal-weight production RRF inside H0/H2 base).

## Acceptance (all required; else MEASURED, no promotion)
- H1-D0 delta >= +0.05 with margin >= +0.003, AND
- H1 beats H0 on BOTH even/odd halves (robustness), AND
- H1-H0 gain > +0.01 (not tiebreak noise), AND
- protocol/validator integrity PASS, AND review approval.

## Integrity
Frozen results.json untouched. New-model cache/params recorded in
cap001_rerank/ revision dir on success only. TEMP scripts only.
