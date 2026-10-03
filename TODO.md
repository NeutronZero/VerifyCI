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
