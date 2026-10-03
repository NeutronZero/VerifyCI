# H3 — Incremental Parse Tail Latency (FROZEN CONTRACT)

Branch: `v1.1`. Status: **CLOSED — UNSUCCESSFUL-BUT-VALUABLE (measured;
landed on v1.1, NOT promoted/merged).** No benchmark/fixture changes.
No H1/H2 changes.

## Frozen reference

- Tag: `v1.0.2-correctness`.
- V1.0.2 remeasured baseline (`V1_EVIDENCE.md:204-207`, same host class
  as the record: Windows, Py 3.14.7):
  - warm median **35.7 µs** (gate <0.2ms: MET)
  - p95 **4.25 ms** (gate <1.0ms: NOT MET)
  - p99 **5.11 ms** (gate <5.0ms: NOT MET, host-unstable across runs)
  - temporal query: met with ~3 orders of margin (not H3's target; regression guard only)
- Historical record (`benchmarks/latency/results.json`): 32.9 µs /
  3.85 ms / 4.27 ms — same unmet classification, host variance only.
- Frozen protocol (`benchmarks/latency/config.json` + `measure.py`):
  N=1000 single-insertion warm parses (`# v{i}` appended at line
  `(i % 37) + 8` of `fixture/workload.py`), `perf_counter_ns` around
  the parse call, gc disabled in-loop, percentiles via
  `ceil(q*n)-1`, one-shot incremental-vs-cold tree-equality preflight.
- Frozen pins: fixture/ byte-exact source copies + hashes, workload
  bytes hash, `test_latency_repro` (median ±50%, tails 3x envelope,
  same classification). `incremental.py` is NOT hash-pinned; the
  timed operation is `IncrementalParser.edit + parse` on the live tree.

## Mechanism (predeclared, from frozen analysis)

Per-edit-line medians span ~20 µs…4.3 ms: cost is edit-position
dependent — tree-sitter re-lexes from the mutation forward, so
early-file edits re-lex a long tail. The 35 µs median proves parsing
IS incremental (cold full parse ~3.7–4.2 ms). Verified in-tree:
`raw_parser()` is already cached per language, so no per-parse parser
construction exists to remove. Expected finding: the tail is
tree-sitter-intrinsic on this workload (answers V1.1 question #5 as
"algorithmic"), and any wrapper-level change moves p95 negligibly.

## Hypothesis

> Hoisting the remaining loop-invariant lookups out of the warm-parse
> call path reduces median cost without changing parse semantics, but
> leaves p95 essentially unchanged — confirming the tail is re-lex
> distance, not VerifyCI-side overhead.

## Experiments (fixed order; one intervention TOTAL)

| ID | Content |
|----|---------|
| H3-A | Baseline reproduction — frozen harness, current tree. Must show median MET (<0.2ms), p95 UNMET (≥1.0ms), temporal MET: same classification as V1.0.2, medians within host-variance bands. Anything else STOPS the campaign. |
| H3-B | Profiling ONLY (no timed-path change): re-derive the per-edit-line cost spread + micro-account the wrapper pieces (`_get_parser` lookup, method fetch, assignment) in scratch, outside the frozen protocol. Predeclared directional claims: (1) the ~20 µs…4 ms position spread reproduces; (2) wrapper-only cost is ≥10× below p95-sample magnitudes. If either fails, the mechanism is wrong → STOP, do not intervene blindly. |
| H3-C | THE single intervention (predeclared now, built after B confirms the mechanism): bind the raw parser + bound `parse` method ONCE before the sampling loop instead of per-call attribute lookups in `IncrementalParser.parse` — zero semantic change to edit application, parse, tree handling, or public API. Predicted: median down slightly, p95 unchanged (NEUTRAL-by-design, mechanism-confirming). |

## Intervention boundary (exact)

At most one edit, confined to `verifyci/ingestion/incremental.py`'s
warm-parse call path as specified above. EXPLICITLY OUT: tree-sitter
itself, workload file/edits, N=1000, timing method, GC/process/env
settings, thresholds (0.2/1/5 ms), temporal-query path, fixture/
copies/hashes, `results.json`, `extractor.py`, `graph_store.py`
(latency-pinned), and any second optimization regardless of B's outcome.

## Failing criteria

- Campaign FAIL: post-intervention p95 still ≥ 1.0 ms (gate unmet).
  This is the EXPECTED outcome; it closes H3 as UNSUCCESSFUL-but-
  valuable with the mechanism verdict, never as license to expand scope.
- Branch STOP (no further passes): median leaves <0.2 ms, temporal
  regresses, tree-equality preflight fails, p95 worsens beyond the 3x
  host band, or any frozen pin breaks.

## Classification (mechanical, vs V1.0.2 35.7 µs / 4.25 ms / 5.11 ms)

IMPROVED only if p95 < 1.0 ms with median < 0.2 ms, temporal met, and
preflight passing. NEUTRAL if p95 moves <15% either way with
classification unchanged (mechanism confirmed). REGRESSED on any
branch-stop condition. Thresholds never retuned, before or after.

## Measurement protocol (single pass per stage)

`H3-A → H3-B (profile) → H3-C (one build) → ONE measure →
classify → STOP.` Same host for all stages (cross-machine claims never
made, per the frozen config). Outputs to `results_h3.json` ONLY —
`results.json`, fixtures, workload, config, and the guard test's
expectations untouched. Full suite + ruff at each code touch; the
latency guard's bands (±50% median, same classification) must hold.

## Environment preconditions

- Same host class as the V1.0.2 record; quiet machine, same Python.
- If the host differs, numeric comparison is void — classification-level
  comparison only, no promotion on numbers.

## Closure record (frozen; landed on v1.1, NOT promoted/merged)

| Metric       |      H3-A |      H3-C |    V1.0.2 |
| ------------ | --------: | --------: | --------: |
| Warm median  |   34.4 µs |   39.4 µs |   35.7 µs |
| p95          |   4.17 ms |   4.58 ms |   4.25 ms |
| p99          |   6.32 ms |   6.35 ms |   5.11 ms |
| Temporal p99 |         — |  0.139 ms | MET       |
| p95 gate     | UNMET     | UNMET     | UNMET     |

- H3-A reproduction: PASS (same classification on every gate, numbers
  inside host-variance bands; `results.json` sha-verified identical).
- H3-B mechanism: position spread reproduced (22.7 µs at line 34 vs
  4473 µs at line 39); wrapper cost ~8.7 µs vs ~4.2 ms samples (~480×
  below). Tail = tree-sitter re-lex distance, not wrapper overhead.
- H3-C (single hoist of the bound parse method): p95 +9.96% vs H3-A,
  inside the ±15% band, classification unchanged → NEUTRAL. No branch
  stop triggered (median/temporal/preflight/pins all held).
- Confirmed mechanism: **tree-sitter re-lex distance**. The predeclared
  wrapper optimization did not improve p95 — negative evidence, not a
  reason to optimize further. No second intervention, no scope expansion.
- Meaningful p95 improvement would require a NEW hypothesis outside
  H3's frozen intervention boundary (e.g. workload-shape, tree-sitter,
  or environment changes — all explicitly out of H3), not an H3 extension.
- Historical measurements preserved side by side (`results.json` frozen
  record, H3-A observed values, `results_h3.json` final); nothing replaced.
- Full suite at landing: 630 passed, 3 skipped, 0 failed; ruff clean.
