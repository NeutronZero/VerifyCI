# CAP-002 experiment: verifier verdict divergence — NOT PROMOTED

Review decision B: keep MEASURED, no v2 re-baseline for promotion.

## Finding

The frozen v1 patch-corpus predicate is jointly unsatisfiable:

```text
exact-status agreement >= 0.90  requires accepting S1-S4  -> FAR = 1.0
FAR <= 0.0                      requires declining S1-S4  -> agreement <= 13/17 = 0.7647
```

No behavior can satisfy both on v1 labels. Recorded 16/17 agreed only by
false-accepting four wrong semantic patches.

## Fresh measurement (TEMP script cap002_diff.py; frozen tree untouched)

| case | expected | recorded | fresh |
|---|---|---|---|
| C3-send-notify | HUMAN_REVIEW | PASS (mismatch) | HUMAN_REVIEW (match) |
| C6-readme-doc | INCONCLUSIVE | INCONCLUSIVE | HUMAN_REVIEW |
| S1–S4 wrong semantic | PASS | PASS | HUMAN_REVIEW |
| all others | — | match | match |

Fresh: agreement 0.7059, catch 1.0, FAR 0.0, precision 1.0, false rejects 0.
Recorded: agreement 0.9412, catch 1.0, FAR 1.0.

## Interpretation

The agreement drop measures stale labels + exact-status bucket granularity
(INCONCLUSIVE vs HUMAN_REVIEW), not capability regression. FAR 1.0 -> 0.0
is a genuine honesty improvement: the verifier now declines semantic
wrongs it cannot judge instead of passing them.

## Why no v2 re-baseline for promotion

Rewriting S1–S4/C6 labels to match observed behavior yields 17/17 only
circularly. Allowed solely as non-promotional research revision, never as
V1 establishment evidence.

## Next capability step (review-directed)

New held-out semantic corpus: author cases, define expected handling BEFORE
any verifier run, freeze + hash, then measure. Expected handling for new
wrong-semantic cases must be justified independently of current behavior.

## Artifacts

- Fresh verdict table: TEMP `cap002_fresh.json` (outside repo; method above).
- Frozen `cases.jsonl`, `config.json`, `results.json`: unmodified.
- Production verifier: unmodified.
- Canonical predicate on frozen evidence: patch = MEASURED (unchanged).
