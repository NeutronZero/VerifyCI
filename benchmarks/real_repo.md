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

## Dense-embedding run: executed (local weights, no daemon)

`all-MiniLM-L6-v2` was in the local cache, so the "blocked on Ollama"
constraint dissolved into a 15-line lazy `SentenceTransformerProvider`
(no download, no server). Same five queries, columns are dense / fused /
reranked per provider (hash vs st):

```text
Q: beam search paths        hash  3/1/1   st  1/1/1
Q: find dma blast radius    hash  1/1/1   st  1/1/1
Q: incremental index dirty  hash  1/1/2   st  5/2/2
Q: weighted shortest path   hash 292/7/2  st  2/2/2
Q: register a new domain    hash  6/2/9   st 29/7/9
```

Neither provider dominates. Real dense fixes the paraphrase pathology
(292→2 on `weighted`) and loses where lexical overlap was carrying
(1→5, 6→29). Fused-with-st beats fused-with-hash on one query, loses on
two. Same caveat as the CE run: all-MiniLM is web-trained, so lexical
losses are expected, not evidence against dense retrieval in general.

What this closes: the dense arm's contribution is now measured rather
than asserted, and fusion-with-either is complementary, not ordered.
What it does not justify: fusing *both* dense providers, per-shape
provider selection, or any new stage — those are decisions for later,
with this table as the baseline. The queue from the reviews is now empty.

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

---

# Real-Repository Measurement — Flask (pallets/flask @ d73fa1c, 2026-09-08)

Cloned depth-10 to temp (not `samples/`). Chosen because it is known ground:
decorators with arguments, `@overload`s, property getter/setter pairs,
nested decorator factories, docstring code examples — the constructs the
extractor had never been measured against. Ground truth in
`benchmarks/score_flask.py`, read file-by-file by a human.

## Ingest

```text
files=99 entities=4119 edges=7672 seconds=4.0
parse+extract total: 0.8s over 83 code files (DB writes dominate at this scale)
top slowest file: tests/test_basic.py 0.190s (505 entities, 1319 edges)
```

No file dominates; no 50k-line generated file in this repo.

```text
entities: PARAMETER 1827, FUNCTION 1055, IMPORT 526, METHOD 376, CLASS 149, MODULE 99
edges: CONTAINS 4163, HAS_NAME 1580, CALLS direct 576, REFERENCES 576,
       IMPORTS 526, CALLS recursive 69, INHERITS 36
```

METHOD/IMPORTS/INHERITS all non-zero — class-scope walk, import extractor,
and inheritance paths all exercised (the `aci stats` smoke check from the
brief passes).

## Extraction (142 hand-read entities, 7 files)

```text
Results: TP=142 FP=0 FN=0
Precision: 1.00  (target > 0.85)
Recall: 1.00     (target > 0.80)
```

With one correction that matters more than the score: the first pass read
TP=142 FP=0 FN=8 (R=0.95), and all 8 "misses" were docstring `code-block`
examples my regex listing had counted as code. Tree-sitter correctly
ignores them; the ground truth was wrong, not the extractor. Corrected the
truth (142 entries), pinned with
`test_docstring_code_examples_are_not_entities`. Lesson recorded:
regex-derived ground truth overcounts on doc-heavy repos; annotation must
be AST-aware or human-read.

Duplicate-identity rate at scale: 87/4103 emitted (2.1%), every case a
same-name/same-scope redefinition (`@overload` triplicates, property
getter/setter pairs, descriptor overloads, duplicate nested defs).
First-wins per the recorded tradeoff; rate now measured, not guessed.

## Queries (dense / fused / reranked × hash / st)

```text
Q: route decorator register url rule
  hash  dense=22 fused=31 reranked=None    st dense=17 fused=20 reranked=None
Q: session cookie secure flag
  hash  dense=3 fused=4 reranked=4         st dense=3 fused=4 reranked=4
Q: stream template generator
  hash  dense=1 fused=1 reranked=1         st dense=1 fused=1 reranked=1
Q: teardown request handler
  hash  dense=10 fused=7 reranked=7        st dense=9 fused=8 reranked=8
Q: class based view dispatch
  hash  dense=1 fused=1 reranked=None      st dense=8 fused=4 reranked=None
```

Reranker drops fused top-1/top-2 off the top-10 twice more (route,
class-view) — the demotion pattern replicates on a second repo. Neither
dense provider dominates (st wins route-fused 20 vs 31; hash wins
class-view dense 1 vs 8 and teardown-fused 7 vs 8; two ties).
Per-arm table stands as the attribution procedure.

## Commits (last 5, real diffs via `git show`)

```text
d73fa1cd | files=['src/flask/app.py']                              | PASS
d318b683 | files=['src/flask/helpers.py']                          | PASS
2a8a38b0 | files=['src/flask/views.py']                            | PASS
d8eaaba8 | files=[] (merge, empty diff without -m)                 | INCONCLUSIVE
89992954 | files=[CHANGES.rst + 2 code files]                      | PASS
```

Distribution 4 PASS / 1 INCONCLUSIVE / 0 FAIL. The merge-commit empty
output is correct behavior on empty input (merges need `-m` handling —
recorded limitation, not a bug). The last commit initially read
INCONCLUSIVE because `CHANGES.rst` (uningestible) vetoed the whole diff;
fixed same session: only ingestible-but-absent files veto
(`INGESTIBLE_EXTENSIONS` single-sourced in `ingestion/language.py`, shared
by ingest collection and grounding). Failing to do this would have made
every docs-touching commit unverifiable — the common case, not the edge.

## Second checker, second real input (forbid_import)

`secrets_scan` was the only checker ever fired on real input. Flask's
sansio split gives a real layering rule: `sansio/` must not import sync
`flask.*`. Current tree is clean (0 violations). Full-history sweep
(1,011 commits' added import lines): rule A (src→tests imports) 0 hits;
rule B — 13 hits, all in commit `0ec7f713` "Split the App and Blueprint
into Sansio and IO parts" (2023-06-11), which created
`sansio/app.py` carrying `..config`, `..ctx`, `..helpers`,
`..templating` imports, cleaned up later. Genuine transitional violation.

Exercised end to end: worktree at `0ec7f713`, full ingest (101 files,
3832 entities, 7246 edges), diff of `sansio/app.py` against
`forbid_import:..config` + `forbid_import:..ctx` → both checks FAIL.
Two checkers, two real historical inputs.

Doing this exposed a real extractor bug first: relative imports recorded
the imported *symbol* (`Config`) instead of the module (`..config`),
which would have made every `forbid_import` rule silently miss relative
imports. Fixed (module-position parsing) with a pinning test.

And a real product gap the exercise forced into the open: `run_verify`
still returns PASS on that diff, because project-specific invariants have
no config surface — `_default_invariants` is hardcoded to secrets +
provenance. The violation is detectable only when someone wires the rule.
Recorded, not built: the next honest feature is project invariant
configuration, not another checker.

## Invariant config surface (built because the sweep demanded it)

The layering exercise forced it open: `run_verify` returned PASS on the
`0ec7f713` diff because project rules had nowhere to live. Now
`<repo>/.verifyci/invariants.yaml` (flat list, same four query kinds)
loads by default in `run_verify`, `run_task`, and both MCP paths, extending
the built-ins — no opt-in flag, or the common path would stay hardcoded.
Proven: a repo-local `forbid_import:typing` rule flips a clean mapped diff
to `FAIL | blocking_check_failed` with zero flags passed.

## On precision, denominators, and coverage signals

- The 13-hits-in-one-commit result is precision evidence, not just a count:
  a rule that fires on its intended target and stays quiet across the other
  1,010 commits has demonstrated precision. Stated next to the number.
- Denominator sharpened: the 1/1011 secrets rate reflects that Flask rarely
  writes secrets-shaped strings into added lines. On a crypto library or
  auth service the rate is not this rate — repo-test-density specifically,
  not "density varies" generally.
- Coverage signals: every `forbid_*` verdict now reports what it examined
  (`examined N CALLS edges for 'x'`), and zero-edge graphs say
  `no <TYPE> edges in graph — vacuous pass`. A vacuous pass is still a pass
  (no violation exists), but it is now a *visible* one — the fourth
  instance of "logic right, data wrong" (LIMIT corpus, CHANGES.rst veto,
  relative-import misattribution, hardcoded defaults) gets the same
  treatment as the metric-honesty work: technically-correct-but-empty
  numbers are confidence-shaped, so they carry their coverage with them.

Denominator warning: 1 hit in 1,011 diffs reads as "well-tuned" only if
you miss the test-tree asymmetry. Flask's test tree is small and fixture
literals like `password="test"` are rare there; on pytest/Django/requests,
where every auth test carries a secret-shaped fixture, the same literal
rule fires constantly. The rate is checker × repo-test-density, not a
property of the checker. Fixture-blindness stays the documented precision
boundary.

## The first real FAIL (secrets_scan)

Full-history sweep: 1,011 commits touching `src/` or `tests/`, every added
line run through `secrets_scan`. Exactly one hit — commit `025589ee`
("Reformat with black"):

```text
verify -> FAIL | blocking_check_failed
files=['examples/tutorial/tests/conftest.py'] changed=54
```

The line is `def login(self, username="test", password="test")` — a test
fixture whose quotes black normalized. By human judgment this FAIL is a
false positive; by the checker's literal rule it is correct. Both halves
are the finding: the FAIL path now has a real (not synthetic) exercise,
and the checker's precision boundary is fixture-blindness. No fix applied —
the tradeoff (literal rule with fixture false positives vs. a
fixture-aware rule risking false negatives on real secrets) is recorded
here for the next decision, not decided here. Note the search itself is the
method: pickaxe `-S` over full history found nothing (framework code only),
the added-lines sweep found one.

## Reverted commits: bad and fix both PASS (discrimination gap named)

Two reverts with src/ Python changes (`c935eace` BaseExceptions,
`5c127217` issue-1809) plus the judged-bad commit they revert
(`12c49c75`):

```text
12c49c75 bad:handle-baseexc    -> PASS (2016-era flask/app.py grounds via suffix match)
c935eace revert:handle-baseexc -> PASS
5c127217 revert:issue-1809     -> PASS
```

The gate cannot distinguish a judged-wrong change from its fix. Both
ground (one via a 7-year layout move the suffix matcher bridges — itself
worth noting), neither trips an invariant. Expected: most real bugs are
semantic. Recorded as the discrimination gap, not a defect.

## Mutation matrix (5 single-defect patches, all real lines)

```text
mut-rename    def renamed, caller dangling       -> PASS
mut-delcall   call deleted (NameError below)     -> PASS
mut-default   default True->False                -> PASS
mut-dropreturn dropped timedelta return          -> PASS
mut-cmp       is None -> is not None             -> PASS
```

Boundary table, stated not inferred:

| defect class | verdict | standing |
|---|---|---|
| rename, caller dangling | PASS | **gap, not scope**: a graph-grounded gate should see a dangling reference; candidate next checker (`no_dangling_calls`), not built |
| deleted call | PASS | outside stated scope (no invariant covers it) |
| default change | PASS | outside stated scope |
| dropped return | PASS | outside stated scope |
| swapped comparison | PASS | outside stated scope |

PASS rationale now reads `all_checks_passed_behavior_not_verified`, so a
reviewer seeing one decision sees the scope qualifier without opening the
README.

## Agent-regenerated patches: 0/20 divergence (stability, not discrimination)

20 small Flask commits; each change regenerated from its message (17 admit
essentially one edit and coincide; 3 doc rewordings plus 1 structural
variant written fresh). Human verdict vs regen verdict per commit:

```text
20/20 PASS/PASS � divergent: 0/20
```

What this shows: the gate is stable under reformulation � same verdict on
reworded docs and on a restructured refactor. What it does not show:
discrimination, because nothing in the set is wrong.

One case deserves precision over comfort. The `a411a243` regen inlines the
session open via the existing `session` property instead of extracting a
`_get_session` helper. That property access sets `accessed = True` as a
side effect; the human version opens without marking accessed. The
behavior differs (cookie/session bookkeeping downstream) and the gate
says PASS on both. That is the exact population the product exists for �
well-formed, subtly behavior-different � and structural verification
cannot see it. Consistent with the documented scope boundary
(provenance + impact, not semantic intent), and the reason the boundary
is stated as a limitation rather than a detail.

Methodology notes: regen patches target parent state; both sides verified
against the current graph. `git show` silently emitted empty output for 5
of the 20 commits (mechanism unknown); `git diff sha^ sha` retrieved them.
PowerShell-redirected patch files land UTF-16 and must be converted before
parsing � second occurrence of the encoding trap, now a checklist item.

# Dogfood: SmartEnergyMeter_3ph (own real work)

Staged copy excluding vendored ESP32 toolchains (9.5k SDK headers),
`__pycache__`, caches, `.env`. 539 project files ingested:

```text
files=539 entities=8742 edges=14340 seconds=42.6 (0.079s/file)
langs: c 4356, python 1904, cpp 1472, markdown 67, txt 34
```

A real C++ firmware feature (`70a46b9` UART bridge via DMA, 3 files):

```text
verify -> PASS | all_checks_passed_behavior_not_verified
files=[main.cpp, uart_bridge.cpp, uart_bridge.h] changed=36
```

First verdict carrying the scope qualifier on real work: 36 entities
grounded, no invariant tripped, behavior explicitly not verified. No
FAIL surfaced � nothing in this pass contradicted the gate, which is
itself recorded rather than celebrated.

# C++ extraction (firmware, blind-annotated): TP=81 FP=0 FN=0

Ground truth in `benchmarks/score_cpp.py`, read file-by-file from the
ra4m1 firmware by an annotator working from C++ structure (not extractor
output): `static`/inline free functions, ISRs, header/source split
(declarations must not emit), a function template (`find_ring_slot`),
forward declarations, `struct`-with-body. Reproduce:
`python benchmarks/score_cpp.py`.

```text
Results: TP=81 FP=0 FN=0
Precision: 1.00  Recall: 1.00
```

The 3 initial FPs were annotation misses again (`static inline`
functions my listing regex skipped: `prv_rx_available`, `i2c_delay`,
`calculate_crc32`) � truth corrected, extractor right, same lesson as the
docstring round: annotation tooling is part of the measurement.

Deliberately excluded and documented as a known gap: `enum class
TripReason` (relay.h) � the extractor has no ENUM mapping. C++ grounding
therefore rests on functions/structs; enum-typed claims are invisible to
the graph. Stated here so the firmware numbers are not over-read.

# Overload/duplicate-key audit + enum-only false PASS (both fixed,
then the PASS un-fixed itself once)

Duplicate `(file, name)` scan across the staged copy found the collisions
are overwhelmingly elaborated type references (`struct foo` in type
position parsed as `struct_specifier`), not overloads: 67 hits of
`libusb_device_handle`-as-CLASS in one vendored file. Struct/class
specifiers without a body (`field_declaration_list`) no longer emit
entities. Separately, an enum-only diff (`TripReason` + enumerator, the
enum unmapped) verified PASS on MODULE-existence alone — the exact false
confidence path predicted. Diffs grounding only to MODULE rows are now
INCONCLUSIVE (`module_only` in the rationale). Both pinned by tests.

Correction appended after the fact: the first INCONCLUSIVE measurement ran
against a stale DB (wipe failed silently; deterministic revision ids
reused the same revision, preserving a phantom row from the old
extractor). Fixed twice: (1) tree-sitter-c parses `enum class X {}` in
`.h` files as a `function_definition` with a bare identifier and *no
declarator* — C/C++ names now require the declarator path, Python keeps
the direct-identifier fallback; (2) wipes are verified with assert, never
`ignore_errors`. Re-ingested fresh, re-measured for real: enum-only diff
→ INCONCLUSIVE, changed=1 (the MODULE row), SEM at 6748 entities (170
phantom CLASS rows gone). The earlier PASS-then-INCONCLUSIVE pair is kept
in this record rather than rewritten, because the stale-DB trap is itself
a finding: deterministic identity makes re-ingest idempotent, which also
means it preserves whatever an older code version wrote.
