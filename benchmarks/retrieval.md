# Retrieval Micro-Benchmark

Offline, dependency-free smoke benchmark for the hybrid retrieval path
(dense hash embeddings + BM25 + graph expansion → RRF → overlap rerank).
Reproduce: `python benchmarks/retrieval_eval.py`.

## Measured output

```json
{
  "queries": 5,
  "recall@5": 0.8,
  "ndcg@10": 0.8663109259167244,
  "dense_only_ndcg@10": 0.8773705614469083
}
```

## What this is and isn't

- IS: regression protection. `tests/evaluation/test_retrieval_eval.py`
  pins recall@5 ≥ 0.8 and hybrid-within-0.05 of dense-only.
- IS NOT: the PLAN.md BEIR-scale gate (hybrid nDCG@10 ≥ dense-only + 5pts
  over 50+ judged queries). That gate needs real embeddings served over the
  `EmbeddingProvider` contract plus judged query sets — still pending.

## Known gap

Paraphrase queries ("how does login work" vs indexed "authentication ...")
miss under lexical signals. This is the documented reason
`OllamaEmbeddingProvider` exists: plug in real embeddings and re-run this
script to measure the delta.
