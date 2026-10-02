# H1 — Retrieval Representation & Fusion (FROZEN CONTRACT)

Branch: `v1.1`. Status: **CLOSED — UNSUCCESSFUL-BUT-VALUABLE. NO PROMOTION.
NO SEARCH-SPACE EXPANSION.** No implementation. No production code
changes. No frozen-file changes.

## Frozen reference

- Tag: `v1.0.2-correctness` (`33405e6`).
- Baseline (`benchmarks/beir/results.json`, 62 queries / 60 docs):
  - dense: Recall@5 `0.6465`, nDCG@10 `0.6220`
  - hybrid: Recall@5 **`0.6707`**, nDCG@10 `0.6603`
  - delta nDCG: **`+0.0384`** (+3.84 pts; gate target +0.05 NOT met — measured-only)
- Frozen inputs (hashes in `results.json`, MUST NOT CHANGE):
  - `corpus.jsonl` (`cac3aa97…`), doc text = `name file_path` (production indexing format)
  - `qrels.jsonl` (`b1debc8b…`)
  - `config.json` (`fdde7985…`): RRF k=60, k_recall=5, k_ndcg=10, model `nomic-embed-text`
- Frozen harness: `benchmarks/beir/eval_harness.py` (validate → embed → rank → score → report).

## Primary hypothesis

> Richer retrieval document representation and/or RRF weighting can
> improve hybrid retrieval on the frozen judged set without degrading
> the dense baseline or introducing retrieval leakage.

## Experiments (frozen set, fixed order)

| ID | Change |
|----|--------|
| H1-A | Baseline reproduction — frozen harness, frozen representation, frozen RRF k=60. MUST reproduce Recall@5 `0.6707` and delta `+0.0384` exactly, else no intervention is valid. |
| H1-B | Doc text + **function docstrings** |
| H1-C | Doc text + **parameter signatures** |
| H1-D | Docstrings + parameter signatures |
| H1-E | RRF `k` alternatives against the frozen representation, via PRODUCTION `rrf_fusion(..., k)` (not the harness-local `_rrf` copy). Predeclared k set: **{20, 60, 120}** (60 = control). |
| H1-F | Best representation × best k, selected by the frozen rule below — decided BEFORE the measurement pass. |

Selection rule (H1-E winner, H1-F inputs): highest hybrid Recall@5;
tie → highest hybrid nDCG@10; tie → smallest change from control
(fewest representation tokens, then k closest to 60). No post-hoc picking.

## Gates

Primary improvement: `Recall@5 > 0.80 AND nDCG@10 improvement >= +5.0 pts over dense`.
Non-regression: dense-only Recall@5 and nDCG@10 must not decrease (per-experiment, vs H1-A).
Evidence integrity: corpus/qrels/judged-query set unchanged; same protocol;
validators pass; no leakage (below). Individual interventions are classified
IMPROVED / NEUTRAL / REGRESSED vs V1.0.2 — missing `0.80 / +5 pts` is not
failure, only non-promotion.

## Failing-first requirement (before any implementation)

Representation-contract tests that FAIL on the current index, e.g. an entity
with a distinctive signature/docstring term must be retrievable by a query
containing that terminology. No retriever changes until these exist and fail.

## Leakage rules

Enrichment text comes ONLY from the indexed entity itself (name, path,
signature, docstring) as present in the **frozen-reference tree**
(`v1.0.2-correctness`) — never qrels, query text, labels, benchmark
metadata, judged neighbors, or annotations. Frozen texts reuse the
content-keyed embedding cache; only NEW enrichment texts may embed fresh.

## Measurement protocol (single pass)

`V1.0.2 baseline → H1-A reproduction → H1-B…F → ONE evaluation pass →
compare vs 0.6707 / +3.84 → classify → promotion decision.` No tuning
after seeing results. Outputs go to `results_h1.json` (or scratch dir) —
`results.json` is NEVER overwritten. Production `verifyci/` paths unchanged
during measurement; scaffolding lives in tests/scratch only.

## Environment preconditions

- H1-A needs NO live Ollama (frozen texts hit the content-keyed cache).
- H1-B/C/D REQUIRE Ollama `nomic-embed-text` at the config URL; if
  unavailable, H1 blocks after H1-A rather than substituting models.
- Full pytest suite green on `v1.1` before H1-A (establishes the branch baseline).

## Stop conditions

Regression in the dense baseline or any integrity/leakage violation stops
that branch immediately. If nothing reaches the improvement gate, H1 is
UNSUCCESSFUL-but-valuable; the search space is NOT expanded to chase the number.

## Closure record (frozen; do not extend)

- H1-A reproduction: PASS (exact: 0.6707 / +0.0384).
- Representation tests: RED → GREEN.
- H1-B docstrings: NEUTRAL (hybrid recall −0.0067; not carried forward).
- H1-C signatures: IMPROVED (+0.0202 recall / +0.0363 nDCG; strongest tested).
- H1-D both: IMPROVED but dominated by C on recall.
- H1-E k ∈ {20,60,120}: NEUTRAL (bit-identical; fusion decides nothing here).
- H1-F (H1-C, k=60): R@5 0.6909 / nDCG 0.6966. Primary gate NOT MET (0.6909 < 0.80).
- Mechanism finding: representation quality decided everything on this
  judged set; RRF weighting decided nothing.
- EXPLICIT NON-PROMOTION: the evidence establishes "signature enrichment
  improved the frozen judged-set measurements." It does NOT establish
  "signature enrichment should be promoted to production retrieval."
  H1-C stays out of production paths. The remaining 0.1091 recall gap is
  NOT to be chased inside H1.
- Evidence: `results_h1.json` (+ `corpus_h1_{b,c,d}.json`, `h1_enrich.py`,
  `h1_measure.py`, `h1_ef.py`, `test_h1_baseline.py`,
  `test_h1_representation.py`). Historical `results.json`, corpus, qrels,
  config, frozen cache untouched throughout.
