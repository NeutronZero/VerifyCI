# V1 Baseline Evidence

Recorded at tag `v1.0.0`. This file preserves the measured numbers behind the
V1 walking-skeleton claim so future work can regress against them. Nothing
here is a target — all values are observed.

## Test suite

```text
146 passed               (full suite)
44 tests collected         (tests/memory: equivalence matrix + ledger + replay)
```

Environment note: 12 of the 137 tests require Tree-sitter grammar packages
(`tree_sitter_python`, `tree_sitter_c`). In environments without them those
12 error at fixture setup; everything else passes dependency-free.

## Extraction benchmark (`python benchmarks/run_extraction.py`)

```text
Results: TP=11 FP=0 FN=0
Precision: 1.00  (target > 0.85)
Recall: 1.00     (target > 0.80)
```

Scope: FUNCTION / METHOD / CLASS over `samples/test-repo` Python files.
MODULE / IMPORT / PARAMETER nodes are structural inventory outside this
ground truth (31 raw entities across the 3 files).

## Retrieval micro-benchmark (`python benchmarks/retrieval_eval.py`)

```text
queries: 5
recall@5: 0.8
ndcg@10: 0.8663109259167244
dense_only_ndcg@10: 0.8773705614469083
```

Offline lexical stack (hash embeddings + BM25 → RRF → overlap rerank).
The PLAN.md +5pt BEIR-scale gate is explicitly NOT claimed; this benchmark
is regression protection only. Known gap: paraphrase queries need real
embeddings (`OllamaEmbeddingProvider`).

## Decisive behavioral matrix (reproduced against `samples/test-repo`)

```text
clean mapped diff      → PASS          → task COMPLETED
hardcoded-secret diff  → FAIL          → task FAILED
unknown-file diff      → INCONCLUSIVE  → task INCONCLUSIVE
```

## V1 scope boundary

Provenance + graph impact + deterministic invariants. Not formal program
verification; not proof of semantic intent. Deferred items live in
CHANGELOG.md under V1.1 / V1.2.
