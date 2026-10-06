# CAP-002 held-out result — MEASURED, NOT PROMOTED

## Measurement (single run, frozen corpus)

agreement 0.8235 (14/17), deterministic catch 0.50, semantic FAR 0.1667.
Predicate requires 0.90 / 0.95 / 0.0 → all three legs fail.

## Falsified predictions (3) — the held-out corpus working as designed

1. **N-W3 secret in db.py → PASS (expected FAIL).** Root cause isolated:
   secrets detection is identifier-name-dependent. `api_key = "sk-live…"`
   matches SECRET_RE; `pwd = "sk-live…"` (identical credential value)
   matches zero patterns. A hardcoded credential under an innocuous
   variable name passes silently. Genuine detector gap (name-pattern vs
   value-entropy detection), not a label error.
2. **N-W4 fabricated removal in util.py → INCONCLUSIVE (expected FAIL).**
   Removal provenance establishes on auth.py (v1 W4) but not on util.py:
   `unestablished_blocking_checks`. Path/context-sensitive proof gap.
3. **N-S4 callers.py recipient swap → PASS (expected HUMAN_REVIEW).**
   My HR rationale was wrong: swapping a string argument preserves call-
   graph shape, so the exposure model sees nothing. Argument-value
   semantic blindness is real and currently undetectable by design.

## Correct predictions (14)

All 7 correct (5 PASS, C3-class HR, new-module INC), 3 deterministic
FAIL (eval/subprocess variants), 5/6 semantic declines. Zero false
rejects. The decline contract holds where blast exposure fires.

## Disposition

- MEASURED. No promotion. Frozen v1 untouched; held-out revision stands
  as the honest record (results.json committed here).
- Next capability work (review-directed): value-based secret detection,
  removal-proof robustness across files, argument-sensitivity analysis.
  Each fix must be validated on NEW held-out cases, never by re-running
  this corpus until it passes.
