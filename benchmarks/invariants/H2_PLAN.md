# H2 — Invariant Recall (FROZEN CONTRACT)

Branch: `v1.1`. Status: **CLOSED — SUCCESSFUL (measured; landing recorded,
NOT promoted/merged).** No frozen-label changes. H1's outcome does not
scope H2.

## Frozen reference

- Tag: `v1.0.2-correctness`.
- Corpus: `tests/evaluation/labels/invariants_v2.jsonl`
  sha256 `e17d65878ccc53305d6c581525524c573fa7fa1615cf2ea29bdf077e38e39011`
  — 26 cases: 18 recall positives (incl. 2 known gaps), 8 true negatives.
- Baseline (same scorer, same loader):
  - Recall `16/18 = 0.889`, Precision `1.00` (16/16), Coverage `1.00`.
  - `secrets_scan` alone `11/12 = 0.917`.
- Scorer: `score_labeled` (`verifyci/verification/intent_align.py`) over
  the frozen loader (`load_v2_cases` shape: diff + invariant + graph +
  evidence + expected). Same scorer, same fixtures, every pass.
- Gate (unmet): Recall ≥ 0.90 (needs ≥17/18), Precision ≥ 0.85.

## Known residuals (hypotheses to TEST, not fixes to assume)

1. `v2-gap-relative-import` (mechanism `graph_relative_import`):
   graph fixture `from ..config import Config` + `Config.load()`,
   invariant `forbid_import:config`, unattributed diff. The resolver
   never links `..config`, so no IMPORTS edge fires.
2. `v2-gap-short-unquoted` (mechanism `unquoted_below_floor`):
   added line `AWS_SECRET_KEY=shortVal` (8 chars). Below the
   documented 12-char `UNQUOTED_SECRET_RE` floor, so `secrets_scan` misses.

## Experiments (isolated; NEVER combined in measurement)

| ID | Hypothesis |
|----|------------|
| H2-A | Baseline reproduction — `score_labeled` on the frozen loader reproduces Recall `16/18`, Precision `1.00`, Coverage `1.00` EXACTLY (not within epsilon). Mismatch STOPS the campaign. |
| H2-B | Resolving `.`/`..` relative imports via the source file's package hierarchy recovers the relative-import residual with no false positives. |
| H2-C | Extending detection for the sub-12-char unquoted-secret case recovers that residual with no precision loss on the frozen negatives. |

## Failing-first tests (to be created, must fail pre-implementation)

- H2-B RED: `from ..config import X` in a package-hierarchy fixture
  links an IMPORTS edge to module `config` (graph side fires
  `forbid_import:config`); companion negatives — `from ..other import Y`
  must NOT resolve to `config`; absolute imports byte-identical behavior.
- H2-C RED: `AWS_SECRET_KEY=shortVal` added line FAILS `secrets_scan`;
  companion: all 8 frozen negatives still pass (precision pinned at 1.00).
- Placement mirrors H1: `tests/evaluation/test_h2_invariant_*.py`.
  No retriever/resolver changes before these exist and fail.

## Gates

- Primary: Recall ≥ 0.90 AND Precision ≥ 0.85 (frozen V1 rule).
- Non-regression: Precision stays `1.00` on the frozen 26-case corpus;
  any precision drop stops that branch immediately.
- Per-intervention classification vs V1.0.2: IMPROVED (residual
  recovered, no regression) / NEUTRAL / REGRESSED. Thresholds are not
  tuned after seeing results.

## Measurement protocol (single pass per branch)

`H2-A → H2-B RED → implement → GREEN → measure B alone →
H2-C RED → implement → GREEN → measure C alone → classify.`
B and C are never measured combined (a combination is a separately
authorized follow-up, if ever). Outputs go to
`benchmarks/invariants/results_h2.json` ONLY — labels, the baseline
test constants, and all historical evidence untouched. Production
wiring only at promotion; scaffolding in tests/scratch.

## Promotion / non-promotion rule

Promotion requires: primary gate met AND precision 1.00 AND full suite
green AND zero frozen-label edits. Otherwise the outcome is recorded
as UNSUCCESSFUL-but-valuable (H1 precedent): no promotion, no
search-space expansion, no threshold retuning.

## Stop conditions

H2-A mismatch → full stop. Precision < 1.00 → that branch stops.
Any edit to frozen labels/constants → measurement invalid. Any
threshold or scope change after results → forbidden.

## Closure record (frozen; landed on v1.1, NOT promoted/merged)

- H2-A reproduction: PASS exact (16/18, 1.00, 1.00).
- H2-B isolated: 17/18, precision/coverage 1.00 — relative-import
  residual recovered (`..config` links via IMPORTS last-component
  matching; extractor untouched per latency freeze). Record preserved
  under `h2_b` in `results_h2.json`.
- H2-C isolated: short-secret residual recovered (AWS secret-key
  family, 8-char floor; generic 12-char floor unchanged).
- Final combined B+C (`final` in `results_h2.json`): **18/18 = 1.000,
  precision 1.00, coverage 1.00. Gate PASS. Classification IMPROVED.**
- Trajectory: 16/18 → 17/18 → 18/18, precision 1.00 throughout, no
  combined-measurement surprise.
- Non-regression: precision and coverage held 1.00 at every stage.
- Historical checkpoints preserved: pre-intervention 16/18 (H2-A
  record, comments), post-B 17/18 (H2-B record + file history),
  final 18/18 (asserted with notes, not overwritten meaning).
- `added_refs` lexical path deliberately untouched (recorded follow-up).
- Full suite at landing: 630 passed, 3 skipped, 0 failed; ruff clean.
