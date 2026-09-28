# Real-Repository Measurement — Graph-RAG

First non-trivial evidence for VerifyCI. Target: `Graph-RAG` (firmware
graph-RAG assistant, ~1.1k files), ingested from a content copy excluding
`.git`, `__pycache__`, caches, and `.env`. 920 files staged, 472 matched
source extensions (Python, C, Markdown, text).

Reproduce: stage the copy, then `run_ingest(copy)` /
`python benchmarks/score_real_repo.py`. Ground truth lives in
`benchmarks/score_real_repo.py` (hand-annotated from source, scope-checked).

## Ingest (full)

```text
files=472 skipped=0 entities=6676 edges=10026 seconds=51.1
DB: 14.8 MB SQLite
entities by language: python 6515, markdown 132, c 21, txt 8
edges by type: CONTAINS 5009, IMPORTS 1809, CALLS 1208, REFERENCES 1187
```

DB row counts match emitted counts exactly (6676/6676, 10026/10026) — zero
silent loss after the fixes below.

## Ingest (incremental, one file changed)

```text
files=1 skipped=471 entities=6677 carried=6641 closed=35 seconds=5.9
parent_revision_id linked: True
latest revision complete: True (probe + pre-existing entity both present)
```

## Extraction (149 hand-annotated entities, 10 files)

```text
Results: TP=149 FP=0 FN=0
Precision: 1.00  (target > 0.85)
Recall: 1.00     (target > 0.80)
```

Caveat: annotated files skew toward clean module-level code; async,
decorated, and deeply nested edge cases are underrepresented beyond the six
nested-function cases included (`get_transitions`, `decorator`, `wrapper`,
`run_bench`, `clean_val`, `weight_fn`).

## Queries (spot-check, not a benchmark)

```text
Q: find dma blast radius
    0.000 find_dma_blast_radius @ mcp\mcp_server.py        <- exact hit first
    0.000 firmware-embedded.md, candidate_ms, ...           <- noise
Q: beam search paths
    0.000 search @ evaluation/benchmark_runner.py           <- miss
    ... beam_search_paths absent from top 5                 <- genuine miss
Q: incremental index dirty files
    0.000 run_incremental_index, get_transitive_dirty_files <- 2/5 relevant
```

All scores tie at 0.000: hash-trigram cosine saturates on this corpus and
BM25 carries the ranking. Retrieval works end-to-end (EvidencePack: 5
entities / 5 chunks / 5 provenance each) but ranking quality is the weakest
measured area — exactly the gap `OllamaEmbeddingProvider` exists to close.
Next measurement: re-run these three queries with real embeddings and record
the delta.

## Verify / run on a real diff

`git diff HEAD~1 -- retrieval/context_assembly.py` (166 lines, real refactor):

```text
verify -> PASS | all_checks_passed | files=['retrieval/context_assembly.py'] changed=69
run    -> COMPLETED (decision None: all gates passed, no review needed)
```

(Methodology note: an early attempt piped the diff through PowerShell
redirection, producing UTF-16; the parser correctly found no `+++` lines in
that garbage and returned INCONCLUSIVE. Re-ran with clean UTF-8.)

## What measuring found (fixed same session)

- Duplicate IMPORT entities per file collapsed on REPLACE (~90 rows lost) →
  deduped at extraction; entity rows now match emitted 1:1.
- Parallel call sites shared one edge id (~1355 rows lost) → call-site
  line:byte-offset in CALLS/REFERENCES ids; edge rows match 1:1.
- Per-row commits: full ingest 270.5s → 51.1s (`GraphStore.batch()`); naive
  incremental carry-forward 454.6s → 5.9s (fetch-once-per-revision).
- Deleted entities never closed (stayed live forever) →
  `close_deleted_file_version`; asOf queries no longer filter `t_expired`,
  so valid-time history survives transaction-time expiry (tested).
