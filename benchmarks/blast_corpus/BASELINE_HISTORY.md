# Blast Corpus Baseline Measurement History & Lineage

> **Corpus**: `benchmarks/blast_corpus/`  
> **Initial Frozen Evaluation Date**: 2026-10-01  
> **Re-baseline Review Date**: 2026-10-03 (CAP-003)

---

## 1. Initial Frozen Baseline Measurement (`v1.0-evidence-baseline`)

The original frozen baseline evaluated VerifyCI blast-radius coverage against a labeled ground-truth topology (`fixture/src/core.py` + `src/app.py`):

- **Measured Coverage (All)**: `0.8571` (6 / 7 non-empty cases detected)
- **Measured Coverage (Seeded Only)**: `1.0` (6 / 6 validly seeded hunks detected)
- **Total False Positives**: `1` (case `B5`: def-line hunk context window bleed into adjacent function)
- **Gate Verdict**: `NOT MET` (`coverage_all 0.8571 < 0.90`)
- **Structural Gap Identified**: `B6` (`B6-hub-tail-insert`):
  Pure insertion after the hub function's last line was missed because hunk-line based entity seeding yielded `changed_entities = []`. Traversal was intentionally not repaired at freeze time to document this structural boundary.

## 2. Re-baseline Under CAP-003 (`cap003_tail_seeding`)

Under CAP-003, post-freeze diffmap commits addressed tail-insertion seeding:
- Span-intersection logic in `diffmap` was upgraded to attribute insertions immediately following function bodies to enclosing functions.
- `_is_seedable` filter was established to exclude `PARAMETER`, `IMPORT`, and `VARIABLE` entities.
- Re-classification protocol was frozen independently in `cap003_tail_seeding/MODE_PROTOCOL.md` prior to measurement.
- Re-measured coverage reached `1.0` (9 / 9 cases), promoting the capability while preserving the historical 0.8571 baseline in git commit `89340b4d53cd9e8c308330684720711b366c65e9` and `cap003` reference configurations.
