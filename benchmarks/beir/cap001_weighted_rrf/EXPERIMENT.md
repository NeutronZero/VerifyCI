# CAP-001 experiment: weighted RRF (w_sparse = 3.0) — NOT PROMOTED

## Result

Frozen grid search (offline, frozen cache, exact production tiebreak
semantics, baseline replicated to 1e-6 first):

| variant | delta |
|---|---|
| frozen production (equal weights, k=60) | +0.0384 |
| rrf_k=1 | +0.0457 |
| w_sparse=2.0 | +0.0459 |
| **w_sparse=3.0** | **+0.0509** |

Gate needs `>= +0.05`. The best variant clears it by `0.0009`.

## Why not promoted

1. **Tuned on the eval set.** The weight was selected post-hoc on the same
   62 queries it is scored on. No held-out split exists (all 62 frozen
   queries are the gate set). Promoting the argmax over tunings as a
   capability claim is threshold gaming, not evidence.
2. **Noise-level margin.** `0.0009` on 62 queries is a single-query
   rank-swap away from failure. A claim this close to the gate with no
   margin analysis is not establishment-grade.
3. **Product impact unreviewed.** Changing production fusion weights alters
   every query VerifyCI serves, beyond this corpus. No product review,
   no second-corpus validation.
4. **Bundle untouched.** `benchmarks/beir/results.json` (frozen) and
   `verifyci/evidence/claims.py` are unchanged. Canonical predicate still
   yields H1 = MEASURED on frozen evidence.

## What would earn promotion

- A weight (or any fusion change) chosen **a priori** with justification,
  validated on a **held-out query split** or second corpus, with margin
  analysis; or
- A genuine retrieval improvement (embedding model upgrade as new-model
  experiment, graph-channel inclusion with ablation) that clears the gate
  with margin.

## Artifacts

- `config.json`: this revision's parameters + frozen reference.
- Grid table: TEMP `cap001_grid.json` (outside repo; method recorded here).
- Production code: unmodified.
