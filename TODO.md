# TODO — findings backlog (diagnosed, fix out of scope unless noted)

## 1. Macro-invocation entities pollute FUNCTION namespace on C (diagnosed 2026-10-03)

Source: Linux v6.6 boundary probe (`LINUX_TEST.md`, Tier 5).
Status: implemented in `3bb212e` — structural `function_declarator` guard in `_classify_node` (`verifyci/ingestion/extractor.py:464`).

- Scale (Tier 1 `kernel/sched/` alone): 73 `macro(arg) {` sites →
  43 phantom FUNCTION entities (`clamp_id`, `i`, `cpu`, `node`, `pgdat`, `class`) →
  204 phantom edges (34 resolved CALLS stolen from the real enclosing function,
  134 CALLS_UNRESOLVED, 34 REFERENCES) + forced ambiguity (34 entities, 3 names).
- Mechanism: statement-position macro with braces (`for_each_clamp_id(clamp_id) {`)
  is promoted by tree-sitter-c to `function_definition`; the extractor trusts the
  node type (`verifyci/ingestion/extractor.py:400`) and the loop variable becomes
  the entity name. Distinct from H1's declaration-position macros.
- Distinguisher (no heuristic needed — node shape differs). Real definition:
  `function_definition → primitive_type + function_declarator → parameter_list`.
  Macro promotion: `function_definition → type_identifier +
  parenthesized_declarator`, **no `function_declarator` anywhere**. Reproduced
  with `TreeSitterParser` on a 6-line snippet (real vs macro-brace cases).
- Affected example: `kernel/sched/core.c:2002-2005` — FUNCTION `clamp_id` from
  `for_each_clamp_id(clamp_id) {` inside `uclamp_fork`.
- Recommended fix: require a `function_declarator` descendant outside any nested
  body for C/C++ `function_definition` entities. Cheap, precise, V1-worthy.
- Decision (landed `3bb212e`; verified 2026-10-05): snippet repro
  `for_each_clamp_id(clamp_id) {` inside `uclamp_fork` yields only
  `uclamp_fork` + real callees — no phantom `clamp_id` FUNCTION, no phantom
  edges. Closes the 73→43→204 Tier-1 pollution structurally.

## 2. Blast-radius seeds include parameters; traversal includes REFERENCES (diagnosed 2026-10-03)

Source: corrected Tier 4 rerun (`LINUX_TEST.md`), 5 HUMAN_REVIEW patches.
Status: implemented — `fe87078` excludes PARAMETER/IMPORT/VARIABLE from seeds
(`verifyci/verification/diffmap.py:688`) and REFERENCES from traversal
(`verifyci/graph/traverse.py:13`). Re-measured 2026-10-05.

- Terms per patch (seeds → callers / callees → risk):
  650cad561cce 5 seeds → 9 / 1 → 0.95; 8dafa9d0eb1a 4 → 9 / 19 → 1.0;
  9e0bc36ab07c 4 → 1 / 15 → 0.85; cff9b2332ab7 5 → 1 / 24 → 1.0;
  d2929762cc3f 4 → 9 / 19 → 1.0. Formula
  `min(1.0, callers*0.1 + callees*0.05)` (`verifyci/retrieval/blast_radius.py:49`);
  `test_coverage_gap` contributes 0 (empty `test_entities` → `[]`, by design).
- The saturation is arithmetically real but input-noisy: seed names per patch are
  `['avg_vruntime', 'avg_vruntime_update', 'cfs_rq', 'delta']`,
  `['cfs_rq', 'reweight_entity', 'se', 'weight']`, etc. — 1 real changed function
  plus parameters/struct names. `_is_seedable`
  (`verifyci/verification/diffmap.py:659`) excludes only MODULE, so PARAMETER
  entities overlapping the hunk seed; CALL_FLOW_TYPES
  (`verifyci/graph/traverse.py:12`) includes REFERENCES, so a seed parameter
  fans out to every function touching that name. Junk seeds × REFERENCES
  fan-out saturates every real patch.
- Candidate fix (post-release, verdict-changing — do NOT land without corpus
  re-measurement on `patch_corpus`/`blast_corpus`): exclude PARAMETER (and
  IMPORT) from seeds — the enclosing FUNCTION spans the same hunk lines and
  seeds anyway, so nothing is lost. Separately consider CALLS-only traversal;
  that is a semantic change, not a filter.
- Decision (landed `fe87078`; re-measured 2026-10-05): blast `coverage_all`
  0.8571→1.0 (MET, `coverage_seeded_only` 1.0); seeds halve per case (2→1,
  4→2); B6 tail-insert gap closed (0→1 seed, recall 0→1.0); total_fp stays 1
  (B5 def-line). Patch `equivalence` 0.875 unchanged (C3 PASS→HUMAN_REVIEW now
  matches expected; C6 INCONCLUSIVE→HUMAN_REVIEW offsets), `precision` 1.0 MET,
  zero false FAIL. Old pre-ship caution retained below for history.

## 3. TypeScript method decorator span drop (diagnosed 2026-10-04)

Source: post-Phase-2 adversarial audit, finding 11 (LOW).
Status: implemented — sibling-decorator walk-back in `extract_entities`
with latency re-baseline (`measure.py` re-run, `fixture/extractor.py`
refreshed, `results.json` regenerated).

- Mechanism: tree-sitter-typescript nests no `decorated_definition` wrapper;
  `class_body` holds `decorator` as a sibling of `method_definition`, so
  `extract_entities` records the method span without its decorator lines
  (`verifyci/ingestion/extractor.py`, G-01 parent-inherit branch).
- Fix requires touching `extract_entities`, whose source is pinned by the
  latency frozen-source guard (`tests/evaluation/test_latency_repro.py`,
  extractor exception set must stay empty — widen only via re-measure per
  `bb2a013` precedent: refresh `benchmarks/latency/fixture/extractor.py`
  + re-run `benchmarks/latency/measure.py`).
- Decision: LANDED with benchmark re-run (`measure.py`, fixture +
  `results.json` refreshed per `bb2a013` precedent); decorator-only
  edits to TS methods now ground to the decorator span.

## 4. Line-1 config-fragment false FAIL (diagnosed 2026-10-04)

Source: post-Phase-2 adversarial audit, finding 6 (HIGH as stated).
Status: implemented — fragments of existing files decline
(INCONCLUSIVE); brand-new files with invalid content still fail.
Pinned tests updated to the new contract with new-file FAIL cases
preserving fail-closed coverage.

- Mechanism: `_validate_configuration_diff`
  (`verifyci/verification/semi_formal_reason.py`) parses hunk-lines-only
  content as a full document. A valid mid-file edit near line 1
  (e.g. `package.json` version bump, `@@ -1,4`) yields a fragment that
  fails `json.loads`/`tomllib.loads` and returns `fail`.
- Remediation (fragment → INCONCLUSIVE unless brand-new file) flips 7
  pinned tests that require `fail` on invalid line-1 fragments
  (`test_invalid_config_fails_verify`, `test_yaml_valid_and_invalid`,
  `test_json_fragment_valid_invalid_multi_hunk`,
  `test_tests_plus_invalid_config_fails`,
  `test_configuration_only_diff_validates_schema`, plus the
  `multi_hunk_json_configuration` reasoning-string pin). Distinguishing
  "invalid content" from "valid fragment" needs base-file content the
  gate does not load.
- Decision (landed): fragment → INCONCLUSIVE, new-file invalid → FAIL.
  INCONCLUSIVE routes to HUMAN_REVIEW, never PASS, so no silent
  acceptance; fail-closed coverage for genuine new files is pinned by
  new-file FAIL cases in the updated tests.

## 5. Qualified C/C++ call sites degraded to bare names (diagnosed 2026-10-05)

Source: roadmap items 3–4 (name-centric resolution). Deferred resolver
linked `ns::Base` bases canonically but `ns::helper()` calls degraded to
bare `helper` (`_extract_callee_name` keeps the last identifier), so a
qualified call with a same-named top-level entity stayed ambiguous
(resolved 0, ambiguous 1) instead of linking `base.cpp`.
Status: implemented — `_extract_callee_qualified`
(`verifyci/ingestion/extractor.py`) preserves the raw `ns::name` on
`CALLS_UNRESOLVED` metadata; builder matches it against the call-target
qualified index first (`verifyci/graph/builder.py`), canonical-only with
no bare fallback. Pinned by `test_qualified_call_resolves_canonically`,
`test_qualified_call_to_missing_stays_unlinked`,
`test_bare_call_with_two_namespaced_defs_stays_ambiguous`
(`tests/graph/test_deferred_resolution.py`). Blast/patch corpora
re-measured unchanged (blast 1.0 MET, patch equivalence 0.875 /
precision 1.0); latency fixture + `results.json` re-baselined per guard
precedent (plus a harness repair: `build_scale_db` now seeds `rev_0..4`
revision rows for the FK-enforcing writer).

## 6. Deferred links carry no resolver provenance (diagnosed 2026-10-05)

Source: roadmap items 5 (edge confidence) + 8 (revision semantics).
Every deferred link stamped only `{"deferred": True}` — a later reader
cannot tell a canonical `ns::helper` match from a bare unique-name
guess, the exact distinction item 5 wants to weight.
Status: implemented — `_link_resolved`
(`verifyci/graph/builder.py`) stamps `resolver` =
`unique-bare-name` | `qualified-canonical` alongside the surviving
`callee`/`callee_qualified`/`caller_scope` reference. Direct
intra-file links stay unstamped (AST-direct by construction).
Deliberately unconsumed: nothing weights it into risk yet — that is a
separately-measured change. Pinned by
`test_resolved_links_carry_resolver_provenance` and
`test_qualified_resolved_links_carry_canonical_resolver`
(`tests/graph/test_deferred_resolution.py`). Corpora re-measured
unchanged, as designed.

## 7. Reranker ignores symbol identity (diagnosed 2026-10-05)

Source: roadmap item 9. `OfflineReranker` scored pure token overlap,
so `where is parse defined` ranked a `parse`-dense doc above the
`parse` entity itself.
Status: implemented — fixed exact-symbol (+0.5) and qualified-path
tail (`App.run`, `ns::helper` → +0.3) bonuses in
`verifyci/retrieval/reranker.py`, case sensitive, deterministic.
Deliberate omissions: ambiguity penalty and caller/callee proximity
need index-wide statistics the `rerank()` signature cannot see —
that is a pipeline-signature change, not a scoring tweak. Pinned by
3 new tests (`tests/retrieval/test_reranker.py`); smoke eval parity
(hybrid ndcg 0.8773 == dense, bonuses correctly dormant on
non-symbol queries). Frozen BEIR path untouched (rerank default-off,
not in the measured harness).

## 8. False PASS had no explicit accounting (diagnosed 2026-10-05)

Source: roadmap item 12. Patch metrics rated `semantic_false_accept`
but never listed WHICH wrong patches the gate passed — the costliest
outcome deserves names, not just a rate.
Status: implemented — `wrong_accepted_ids` in
`benchmarks/patch_corpus/measure.py::compute_metrics` (+ print).
Additive key only; frozen-record tests compare key subsets, still
green. Current value: the 4 documented semantic wrongs (V1 scope
limit, not a surprise).

## 9. Frozen-baseline protocol (process fix, 2026-10-05)
Re-measurement must never overwrite `benchmarks/*/results.json`:
those files are the frozen historical record pinned by
`test_recorded_metrics_are_stable`-style guards. Two turns of
re-runs clobbered blast/patch baselines (restored from git; guards
green again). Protocol from here: back up `results.json`, run
`measure.py`, restore the file, record deltas in test POSTFIX
constants + TODO evidence notes. `benchmarks/latency/results.json`
is the exception — its own guard mandates regeneration on
measured-path changes.

## 10. Deliberately deferred (roadmap remainder, 2026-10-05)

Each item below was evaluated against the codebase and deferred with
its unblock condition — not from inaction, but because the safe
version is either done above or the full version needs a migration
or calibration that does not exist yet:

- Qualified names in logical identity (items 3+4 full): rewriting
  `compute_logical_entity_id` to include `qualified_name` renames
  every stored entity, breaks replay equivalence (44 tests),
  golden vectors, and every shared DB. Unblock: identity migration
  plan (dual-write + backfill + re-ingest protocol). Metadata
  (`scope`, C++ `qualified_name`) already carries the data.
- Dotted qualified calls for Python/TS (`obj.method` → `Class.method`):
  needs type information the AST does not have; resolving it by bare
  name today is recall-over-precision and any "smarter" guess invents
  impact. Fail-closed (unique-name-or-unlinked) stays. Unblock:
  import-alias + assignment type tracking.
- Confidence-weighted blast risk (item 5 full): weights without
  calibration are false precision. The `resolver` stamp (item 6
  above) is the measurement hook; weighting lands only with a
  labeled corpus showing safer verdicts. Unblock: calibration data.
- Evidence-graph link fields (item 6 full): `Certificate` already
  carries premises + evidence + traces + conclusion with IDs, and
  premise.source joins evidence.file_path today. New cross-link
  fields mean frozen-contract changes with no consumer. Unblock: a
  consumer (e.g. an explainer) that reads them.
- Incremental graph mutation + revision deltas (items 7+8 full):
  `IncrementalParser`, content-identity revisions, and the
  append-only ingest chain exist; per-revision changed-entity/edge
  sets need a storage migration. Unblock: schema proposal.
- Verification budget tiers (item 10): `FilePartition` already routes
  fast paths; a tier enum with no planner consumer is dead code.
  Unblock: a planner that reads it (V2).
- Cross-language normalized IR (item 11): five extractors with
  passing per-language suites; unifying them is a rewrite with no
  failing test demanding it. Per core principle 6: no new subsystem
  without an evaluation showing the current one fails.
- V2 agentic items (14–18): require the above foundations first.

## 11. Identity evidence layer (revised-roadmap A, 2026-10-05)

`verifyci/graph/identity_evidence.py::collision_report` measures
bare-name collisions WITHOUT touching persistent identity: groups of
2+ same-named callables with per-signal separability
(qualified_name/scope/file/type/span). Measured on VerifyCI itself
(101 files, 2319 entities): 38 groups, 121 entities, ZERO
unseparable — every group already separates in stored metadata
(`__init__` x28 by scope alone). Consequence: an ID migration buys
nothing for separability on real code; the residual problem is
call-site MATCHING, not identity storage. Second finding: for pure
separability, `qualified_name` adds nothing over (scope, file) — its
value is canonical matching in the resolver (pinned by test).
6 tests (`tests/graph/test_identity_evidence.py`).

## 12. Explicit-class dotted calls (revised-roadmap B, 2026-10-05)

Same-file `ClassName.method()` now links that class's method
directly (`verifyci/ingestion/extractor.py`): the receiver names the
scope, so it beats the bare path (which previously handed
`App.run()` to an unscoped top-level `run`). One level only;
`self`/`obj`/unknown/deep receivers fall through to unresolved —
no type proof, no edge. 4 tests. Corpora re-measured identical
(patch confusion unchanged, blast 1.0/FP 1); latency fixture +
`results.json` re-baselined per guard precedent. Full
instance-type tracking stays deferred (needs assignment/import
type info).

## 13. Resolver calibration rows (revised-roadmap C, 2026-10-05)

`GraphBuilder(collect_events=True)` logs one row per deferred edge —
ref, resolver, outcome, candidate count, caller language, scope
depth, spelled-qualified (`verifyci/graph/builder.py::_record`).
Default off: zero overhead, zero behavior change. Ground-truth
labeling is the future step that turns these rows into per-resolver
accuracy; until then no confidence number exists anywhere by
design. 3 tests. Corpora unaffected.

## 14. Reranker ablation (revised-roadmap D, 2026-10-05)

`OfflineReranker` bonuses are now constructor-overridable and the
smoke harness takes them as kwargs (`benchmarks/retrieval_eval.py`).
Four-way ablation (baseline/exact-only/qualified-only/both):
identical everywhere (recall@5 0.80, ndcg@10 0.8774) — the features
are provably dormant on generic queries, which is the desired
property, but the smoke corpus cannot show them firing. Unit tests
prove they fire on symbol queries. Next measurement needs a
symbol-query corpus (e.g. "where is X defined" over the BEIR code
docs), not more bonus tuning. Reranker frozen until then.

## 15. False-PASS taxonomy (revised-roadmap E, 2026-10-05)

All four false PASSes are reasoning/invariant gaps — grounding,
retrieval, and graph are NOT implicated:
- S1 (`>= 8` → `>= 4`), S4 (`x*2` → `x*3`): behavioral-constant —
  no invariant covers value semantics.
- S2 (`token = check_password`): call-target contract — callee
  exists in-graph, but nothing checks return-type compatibility.
- S3 (`return user`): data-flow — wrong variable returned; V1 has
  no RETURNS-value analysis (`RETURNS` is a reserved edge type).
- S5 (guard removal) correctly declined: the decline path works.
Implication for prioritization: the next false-PASS reduction
comes from check coverage for value/contract semantics, NOT from
more retrieval or graph work. Each future fix must answer: did it
reduce false PASS, or merely move cases to HUMAN_REVIEW?

## 16. False-PASS → check matrix (V1.x verification-quality roadmap)
| Case | Absent premise/invariant | Evidence required | Smallest mechanism |
|---|---|---|---|
| S3 `return token`→`return user` | returned-value contract: no premise states what `login` returns; RETURNS-value analysis absent (`RETURNS` reserved, unemitted) | `-return`/`+return` pair with differing text, one hunk | return-statement swap → HUMAN_REVIEW (non-blocking) |
| S2 `hash_pw`→`check_password` | call-target contract: callee replaced, no return-type premise for either callee | hunk replacing the call target + both callees' signatures | call-target swap → HUMAN_REVIEW (non-blocking) |
| S1 `>=8`→`>=4`, S4 `*2`→`*3` | value-semantics invariant: no check covers numeric literal changes | changed numeric literal in a CODE_CORE hunk | numeric-literal change → HUMAN_REVIEW (non-blocking) |
| S5 guard removal | none — already declined by deletion verification | — | none |

Rule for all three mechanisms: non-blocking (escalate, never FAIL —
a legitimate refactor also changes returns/callees/constants) and
established=True (the diff text IS the evidence). Adjudication
question per mechanism: did false PASS fall without correct-pass
collateral?

### Adjudicated 2026-10-05: return-swap tripwire — KEEP

`verifyci/verification/return_swap.py` (`return_statement_check`,
non-blocking) wired into all three gate sites (CLI `verify.py`, MCP
`verify_diff`, orchestration `executor.py`). Fires only on a
removed/added `return` pair with differing text in one CODE_CORE
hunk; pure additions (C2/C5/C8), pure removals, comments, strings,
and non-code partitions never fire. 6 unit tests.
Corpus verdict (backup/restore; frozen record untouched):
wrong accepted 4→1 (`wrong_accepted_ids == ["S2-wrong-var"]`),
semantic false-accept 1.0→0.25, decline 0→0.75, equivalence 0.875
unchanged, precision 1.0, zero false rejects, correct set untouched.
Bonus: caught S1/S4 too (both swap a `return` expression) — the
mechanism covers the whole return-expression family, not just S3.
POSTFIX constants updated with review note
(`tests/evaluation/test_patch_corpus.py`, opt-in rerun green).
### Adjudicated 2026-10-05: call-target tripwire — KEEP

`verifyci/verification/call_swap.py` (`call_target_check`,
non-blocking) wired into all three gate sites. Fires only when a
removed callee has no identical added callee under an identical
normalized LHS in one CODE_CORE hunk; additions alongside a kept
callee, argument-only changes, LHS renames, comments, and non-code
partitions stay silent. 8 unit tests.
Corpus verdict (backup/restore; frozen record untouched):
wrong accepted 1→0 (`wrong_accepted_ids == []`),
semantic false-accept 0.25→0.0, decline →1.0, equivalence 0.875,
precision 1.0, zero false rejects, correct set untouched.
Verdict: **KEEP**. POSTFIX updated with review note (opt-in rerun
green). Combined with the return-swap tripwire, the corpus now has
ZERO false PASSes. Remaining matrix row: numeric-literal change
(S1/S4 already decline via return-swap — a literal-change check
would only relabel their rationale, so it stays unbuilt until a
case needs it).

### Campaign CLOSED 2026-10-05: zero false PASSes, freeze

Admitted mechanisms and only these: `return_statement_check`
(S3+S1+S4), `call_target_check` (S2). Admission rule going
forward: a new verification mechanism lands only on a newly
OBSERVED false PASS with (a) matrix row naming the absent
premise, (b) predicted zero correct-case collateral, (c) corpus
adjudication confirming it. Roadmap speculation alone admits
nothing. Frozen state verified: patch/blast/latency guards green,
frozen `results.json` records untouched, POSTFIX carries current
capability with review notes.
