# CAP-003 mode-classification protocol (FROZEN)

Determines each blast-corpus case's `mode` from pre-run fixture/diff
geometry only. No detector output may influence the classification.
Frozen before the promotional measurement; reviewed before use.

## Rule

For case with unified `diff` touching file `F` in the fixture:

1. Parse hunk headers `@@ -old_start,old_count ... @@` from the diff.
   Old-side line set = union over hunks of
   `[old_start, old_start + old_count)` (`old_count` defaults to 1 when
   omitted; pure-insertion hunks with `old_count == 0` contribute the single
   anchor line `old_start`).
2. Parse `F` in the fixture with stdlib `ast` (no repo code). Collect
   `FunctionDef`/`AsyncFunctionDef` spans as `(first_def_line, end_lineno)`.
   (Methods included: they are `FunctionDef` nodes in `ast`. Module,
   parameters, imports, and variables never seed: they are not functions.)
3. Intersect: `seeded` iff some function span contains at least one
   old-side line. Otherwise `known_gap` (non-empty expected set) or
   `known_gap_empty` (empty expected set).

## Properties

- Uses only the diff text, the fixture bytes, and stdlib `ast`.
- Never imports `verifyci.*`, never runs ingest/seed/traverse.
- Expected impacted sets are NOT derived here (they come from the fixture
  CALLS topology + 2-hop contract, reviewed separately).
- Deterministic: same inputs always yield the same modes.

## Reference implementation

`gen_modes.py` in this directory. It reads the v1 `cases.jsonl` (for diffs
and expected sets, which it copies through unchanged) and emits the revised
`cases.jsonl` plus `modes.json` (per-case old-lines, intersecting spans,
mode, and rationale). The committed outputs are byte-compared against a
fresh generator run in review.
