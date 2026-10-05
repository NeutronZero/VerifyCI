# CAP-001 held-out protocol (PRE-COMMITTED — binding)

## Question
Does a fusion configuration selected WITHOUT seeing frozen-test results
improve dense+BM25 fusion enough to establish H1 (delta >= +0.05)?

## Dev material (held-out from selection, never the full gate set)
Deterministic even/odd split of the 62 frozen queries by load order:
DEV-A = indices 0,2,4,... (31 queries), DEV-B = indices 1,3,5,... (31).
Same frozen docs/embeddings/scoring/tiebreak as the gate harness.
The full 62-query set is touched exactly ONCE, by the winner, at the end.

## Candidates (coarse, fixed before any dev run)
(w_d, w_s) in {(1,1), (1,2), (1,3)}, rrf_k=60, sparse_k=10,
exact production fusion semantics (insertion-ordered ties).

## Selection rule (no discretion)
score(c) = mean(delta on DEV-A, delta on DEV-B).
Winner = argmax score. Robustness: winner must lead on BOTH halves
independently, else NO-GO (stop, no frozen run).

## Final measurement (single run)
Winner runs once on the full frozen 62-query set.

## Acceptance (all required)
- frozen delta >= +0.05, AND
- margin >= +0.002 over gate (else borderline per Q5, recommend against), AND
- protocol/validator integrity PASS, AND review approval.
Otherwise: MEASURED, CAP-001 stays OPEN.

## Integrity
Frozen results.json untouched. Experiment dir cap001_heldout/ records
this protocol, dev table, final metrics. Prior full-set grid (w3=+0.0509)
is SUPERSEDED and must not influence selection; it is cited only to
explain why this stricter protocol exists.
