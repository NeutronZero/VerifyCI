# TODO — findings backlog (diagnosed, fix out of scope unless noted)

## 1. Macro-invocation entities pollute FUNCTION namespace on C (diagnosed 2026-10-03)

Source: Linux v6.6 boundary probe (`LINUX_TEST.md`, Tier 5).
Status: diagnosed; fix not implemented.

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
- Decision (pre-ship): DEFER to post-v1.1. `verifyci/ingestion/extractor.py` is
  pinned by the latency frozen-source guard, so the fix requires guard
  re-baselining plus corpus re-measurement; it ships as known-pollution (~2.4%
  entities, 204 phantom edges per sched-scale subsystem), not as a surprise.

## 2. Blast-radius seeds include parameters; traversal includes REFERENCES (diagnosed 2026-10-03)

Source: corrected Tier 4 rerun (`LINUX_TEST.md`), 5 HUMAN_REVIEW patches.
Status: diagnosed; fix not implemented pre-ship (see below).

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
- Decision (pre-ship): record and ship. HUMAN_REVIEW on saturated blast is the
  safe direction (escalation, never a false FAIL); changing seed/traversal
  semantics days before release without re-running the eval corpora would trade
  a known-safe over-escalation for unknown verdict shifts.
