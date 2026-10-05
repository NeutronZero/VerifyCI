# CAP-001 half-B characterization — diagnostic, non-promotional

Per-query deltas at w_s=3.0 (62 frozen queries, TEMP-only analysis):

| group | n | sparse_hits mean | dense nDCG mean |
|---|---|---|---|
| zero-delta (fusion immovable) | 29 | ~2.1 | ~0.72 |
| positive-delta (fusion helps) | 19 | 5.37 | 0.38 |
| negative-delta | 14 | — | — |

Half split: A 11 zero / B 18 zero. The halves differ only because the
even/odd split randomly concentrated dense-saturated queries in B —
heterogeneity is per-query dense quality, not half membership.

## Mechanism

Fusion helps exactly where dense is weak (0.38) and BM25 returns signal
(5+ hits). Where dense already scores ~0.72 with ~2 sparse hits, no
fusion weight can move top-10 nDCG: sparse has nothing to contribute
and dense is near ceiling. ~47% of queries (29/62) are in this
immovable class.

## Consequence for CAP-001

Weight tuning is exhausted as a lever: the +0.0509 ceiling is structural
(immovable queries dilute any gain on the movable ones). Genuine paths:

1. Better dense embeddings (raise the 0.38 low end) as a new-model
   experiment with its own cache + config revision.
2. Graph-channel inclusion with ablation (currently excluded by gate
   config with stated rationale; needs its own experiment revision).
3. Query-class-aware analysis: characterize what makes half-B-style
   queries dense-saturated (identifier overlap? short queries?).

Frozen baseline, production code, predicates: untouched.
Per-query table: TEMP cap001_perquery.json (method above reproduces it).
