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

## Learned cross-encoder run (local, no download, no daemon)

`cross-encoder/ms-marco-MiniLM-L-6-v2` was already in the local HF cache
with weights, `torch` CPU present — so the "blocked on Ollama" run had a
local substitute after all (constraint was daemon, not disk). Zero product
code changed: `CrossEncoderReranker(model=...)` loaded it with
`local_files_only` (16s one-time load, ~0.1s/pair). Same five queries,
rerank depth top-50 fused:

```text
Q: beam search paths        fused 1 | off-rerank 1 | ce-rerank 1
Q: find dma blast radius    fused 1 | off-rerank 1 | ce-rerank 1
Q: incremental index dirty  fused 1 | off-rerank 2 | ce-rerank 5
Q: weighted shortest path   fused 7 | off-rerank 2 | ce-rerank 2
Q: register a new domain    fused 2 | off-rerank 8 | ce-rerank 6
```

The learned model reproduces the offline pattern (lifts the mid-pack
lexical match, demotes elsewhere — worse on `incremental`, 5 vs 2), not a
different one. Swapping in a learned reranker does not fix the shape
problem; the failure is upstream (candidate scoring), not in the rerank
weights.

## Decision (provisional): offline reranker defaults off

Recorded, not yet implemented: the reranker should default off and be
re-enable-able per shape, rather than default on. Evidence: 1 lift vs 2
harms offline, and the learned model confirms the harms are structural.
Implement when the next query set re-measures; until then three-column
reporting stays mandatory so no flat result gets misattributed.

## Duplicate-definition aggregation (confirmed)

`rationalevault/mcp/tools.py` defines module-level `get_recommendations`
twice (lines 371 and 815). Stored DB row holds lines 815–856 (last write
wins on REPLACE); the edge resolver returns the first in-memory match
(line 371). Same id both ways, so the collision is invisible: one node
carrying the union of both definitions' edges, with evidence and stored
row disagreeing on line numbers. Reframed from "one-row loss" to
incorrect aggregation. Open option (not adopted): distinct
`revision_entity_id`s (line-included) with shared `logical_entity_id`,
resolver picks last definition per Python semantics — preserves
edit-stability for the common case, correct for the rare one.

## Ollama/dense-embedding run: refined, still open

No `ollama` binary and nothing on `localhost:11434` here — but that turned
out to understate the options: the box holds cached HF weights
(`all-MiniLM-L6-v2` embeddings, `ms-marco-MiniLM-L-6-v2` cross-encoder)
with CPU torch, and `sentence-transformers` is already a dependency. A
local, daemonless dense run is possible without Ollama specifically; the
cross-encoder half above proves the procedure works end to end. The
constraint is someone wiring a thin `SentenceTransformerEmbeddingProvider`
(~15 lines, lazy import) and re-running the per-arm table — recorded, not
done. The question it must answer: does *real* dense move fused ranks
anywhere the hash baseline doesn't, with the reranker column isolating
attribution.

## Scaling note: non-finding

Uncapped corpus loads the whole latest revision per query (6677 docs here).
Relay at 5x the files (2120 matched, 19k entities) ingested at 0.067s/file
vs 0.108s/file on the smaller repo — marginal cost *below* average, so
constant costs dominate and nothing here suggests a quadratic term. Stated
as a non-finding: no cliff observed up to 2120 files / 19k entities. The
100k TODO in `commands/query.py` stands as design note, not as a finding.

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
