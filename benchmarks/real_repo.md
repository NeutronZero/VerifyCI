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

## Queries (spot-check + per-arm diagnostic, not a benchmark)

First run (before the diagnostic below): all scores printed 0.000, one
genuine top-5 miss (`beam_search_paths` absent). Diagnosis, not guessing:

- Raw dense arm is healthy: query/doc norms 1.0, cosine 0.36 on shared
  trigrams. The 0.000 was the reranker's score passthrough (it sorted by
  overlap but returned the input `score=0.0` objects) — a reporting bug,
  now fixed (rerank attaches its own scores).
- The miss was candidate generation, twice over: (a) `LIMIT 5000` on the
  corpus hid 1676 of 6676 entities; (b) whitespace tokenization never
  matches "beam search" against "beam_search_paths" in BM25 or the overlap
  scorer. Fixed with uncapped latest-revision corpus + shared
  identifier-aware tokenizer (`retrieval/textnorm.py`: snake/camel/dotted/
  path splitting, used by both stages so they agree on tokens).
- Third finding: the query searched all revisions including superseded
  rows. Corpus and graph build are now scoped to the latest revision.

Per-arm ranks after the fix (target rank per stage):

```text
Q: beam search paths        BM25 1 / dense 7 / fused 1 / reranked 1 (0.3750)
Q: find dma blast radius    BM25 1 / dense 1 / fused 1 / reranked 1 (0.5000)
Q: incremental index dirty  BM25 4 / dense 1 / fused 1 / reranked 4 (0.3000)
```

All three exact targets rank first after fusion; every arm now contributes
measurably (dense ranks 7/1/1, BM25 ranks 1/1/4 — neither dominates).
Reranked top-5s are topically coherent (BeamSearchResult,
BeamSearchExperiments, test_beam_search_modes, …). Scores are real overlap
fractions, not ties.

## Mid-pack queries: reranker shows both directions

Added queries where fusion lands the target at rank 3–10 (a ceiling-only
test set can only show ties and demotions). Latest-rev corpus:

```text
Q: weighted shortest path between symbols
   fused 7 | reranked 2 | no-rerank 7   <- reranker LIFTS 7->2
Q: register a new domain plugin
   fused 2 | reranked 9 | no-rerank 2   <- reranker demotes
Q: single points of failure
   fused 2 | reranked out-of-top-10     <- reranker demotes off the page
```

Balanced verdict: the overlap reranker lifts mid-pack lexical matches and
demotes when overlap misleads (2 helps vs 2 harms on six queries). It is
not neutral infrastructure — three-column reporting stays mandatory, and
"disable for the shape" is now supported by lifts as well as demotions.

## Scaling: Relay (2120 files matched of 4963 staged)

```text
files=2120 skipped=0 entities=19263 edges=29760 seconds=142.4
DB: 45.4 MB SQLite
```

Profile: 0.067s/file vs 0.108s/file on the smaller repo — sublinear,
fixed overhead amortizing. No cliff at 5x file count; the in-memory
latest-revision corpus (~19k entities) and graph build hold without strain.
The 100k-entity TODO in `commands/query.py` stands, but nothing measured
here suggests a quadratic term: parsing dominates, storage is one bulk
transaction.

One row lost per table (19262/19263 entities, 29759/29760 edges), diagnosed
rather than hand-waved: `rationalevault/mcp/tools.py` defines module-level
`get_recommendations` twice (lines 371 and 815). Same name+scope+file+type
→ same logical id → one row survives, plus its duplicate edge. Fixing this
needs occurrence-indexed identity, which is unstable under edits (insert a
def above and every later index shifts) — a genuine design tradeoff, not a
missed one-liner. Recorded as known residual: duplicate module-level
definitions collapse to first-wins.

## Ollama provider-swap run: blocked in this environment

No `ollama` binary and nothing on `localhost:11434` here, so the framed
run (same three queries, per-arm table, with/without reranker, dense arm
via `OllamaEmbeddingProvider`) is recorded but unexecuted. The question it
must answer: does dense move from rank-7-class noise to signal, and does
fused change — with the reranker column isolating attribution.

## Scaling note

Uncapped corpus loads the whole latest revision per query (6677 docs here).
At 100k entities that stops being viable; the answer is scoped retrieval
(path-prefix filter, or graph-first entity loading) — see the TODO in
`commands/query.py`. Recorded now so it surfaces as design, not as a
future "queries got slow" surprise.

Framed for the Ollama run: the question is not "does retrieval improve"
but "does the dense arm start contributing signal to RRF at all" — per-arm
ranks above are the baseline that will show it. No new subsystem was added
for any of this (Principle 6).

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
  so valid-time history survives transaction-time expiry (tested). The two
  time semantics now live in separate methods (`get_entity_as_of` vs
  `get_current_entity`) with independent tests, so they cannot re-merge.
- Frozen UTF-16 regression fixture (`tests/verification/test_diffmap.py`):
  NUL-interleaved diff garbage yields no seeds, never throws.
