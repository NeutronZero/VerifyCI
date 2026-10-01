# V1 Evidence Baseline

Reference point for the V1.1 improvement campaign: **V1 = implementation-complete,
audit-hardened, empirically characterized. V1.1 = improvement campaign starting
from this frozen evidence baseline.**

Baseline commit range: `d87f812..826de7d` (documentation closure `d87f812`,
then B1 `b7c22fe` · B2 `38faed3` · C1 `e528891` · C2 `8c35494` · C3 `75e5a5d`
+ style follow-up `826de7d`). Tagged `v1.0-evidence-baseline` (annotated;
chosen to not collide with pre-existing `v1.0.0` / `v1.1.0`, which predate
this campaign by 42+ commits).

## State at freeze

| Check | Value |
|---|---|
| Test suite | **515 passed, 3 skipped** (opt-in re-measure guards: `VERIFYCI_PATCH_RERUN` / `VERIFYCI_BLAST_RERUN` / `VERIFYCI_LATENCY_RERUN`) |
| Ruff | clean |
| Worktree | clean |
| Source changes during B1→C3 | **zero** — proof: `git diff d87f812..HEAD -- verifyci/` is empty; `verifyci/` tree hash `07613dad9b0fa44fa653357bd5fb76551d015f07` |
| **No V1.1 tuning has occurred** | every corpus, protocol, label, and gate threshold was frozen before measurement; nothing was retuned after seeing results |

## Frozen artifact hashes (first 16 hex of SHA-256)

| Artifact | Hash |
|---|---|
| B1 v2 labels — `tests/evaluation/labels/invariants_v2.jsonl` | `e17d65878ccc5330` |
| B2 corpus / qrels / config — `benchmarks/beir/` | `cac3aa9750f2e6b8` / `b1debc8b40663c9b` / `fdde798524d295ee` |
| C1 cases — `benchmarks/patch_corpus/cases.jsonl` | `5ff5ab1b4d075559` |
| C2 cases — `benchmarks/blast_corpus/cases.jsonl` | `efbf6b4e12e62fd1` |
| C3 protocol — `benchmarks/latency/config.json` | `efc6451e97f6fc65` |
| C3 frozen sources — `benchmarks/latency/fixture/` | `extractor 2227617ec6cf175e` · `graph_store 9bfc4ec4660ca88f` · `intent_align 2c8eaf9ef89fa944` · `provider b26e2e45e35c928f` · `env 7b373677981a73d3` · `workload bda0404bc84b9ce5` |
| B1 v1 corpus (baseline preserved) | 6/9 reproduced separately; original 17-case file unchanged |

Each re-measure guard (`test_patch_corpus.py`, `test_blast_corpus.py`,
`test_latency_repro.py`, plus B1/B2 pinned-sha tests) fails if its corpus or
frozen sources drift — the numbers below cannot silently redate themselves.

## Every criterion's final classification

Legend: **established** (gate + protocol satisfied credibly) · **measured-met,
not established** (number passes, corpus/scale too small to claim) ·
**measured-unmet** (below gate, recorded honestly) · **unmeasured**.

| # | Criterion (target) | Result | Classification |
|---|---|---|---|
| — | Verification gate semantics (PASS/FAIL/INCONCLUSIVE invariants) | audit-verified; closure matrix bit-reproducible | **established** |
| 13 | Replay equivalence (100%) | 44/44 | **established** |
| 14 | Provenance coverage (100%) | closure item 10 chain on real DBs | **established** |
| 15 | Local-only (zero cloud) | hash default; Ollama opt-in local | **established** |
| 7 | Invariant check coverage (100%) | 1.0 by construction | **established** (supported kinds) |
| 12 | Temporal query <200ms @10K edges | median 0.042 ms, p99 0.080 ms, hit 1.0 | **met on recorded host** (`DESKTOP-9U7ORK8`, Py 3.14.7, Win11); not cross-machine |
| 9 | Invariant precision ≥0.85 | 1.00 (16/16, FP 0 of 8 negatives) | measured-met, not established |
| 10 | Verification precision >0.85 | 1.00 (4/4 FAILs truly wrong) | measured-met, not established |
| 1–2 | Extraction precision/recall (>0.85/>0.80) | 1.00/1.00 on 13-entity smoke | measured-met, not established |
| 3 | Retrieval Recall@5 >0.80 | 0.6707 (62 judged queries) | **measured-unmet** |
| 4 | Retrieval nDCG@10 +5–15 pts over dense | +3.84 pts (0.6603 vs 0.6220) | **measured-unmet** (smoke 5-query result stays historical) |
| 5 | Patch equivalence >0.90 | 0.875 (7/8 correct → expected outcome) | **measured-unmet**; corpus is synthetic stand-ins — limitation stated, not hidden |
| 6 | Blast coverage >0.90 | 0.8571 (6/7 non-empty cases) | **measured-unmet**; mechanism isolated (see below) |
| 8 | Invariant recall ≥0.90 | 0.889 (16/18) | **measured-unmet**; two pre-declared residuals |
| 11 | Incremental parse median/p95/p99 (<0.2/1/5 ms) | 33 µs / 3.85 ms / 4.27 ms (this record) | **measured-unmet at p95** |
| — | Agent-patch corpus = recorded LLM output | — | **unmeasured** (V1.1 #2) |
| — | Cross-machine latency | — | **unmeasured** (V1.1 #5) |

## Known failure mechanisms (measured, frozen, NOT repaired)

1. **Blast-radius seeding geometry** (limits criterion 6): *Blast traversal
   achieves complete labeled coverage for all successfully seeded changes
   (seeded-only coverage 1.000, contract-level FNs 0); overall coverage is
   85.7% because diff→entity seeding fails on a known trailing-insertion
   geometry (B6: pure insertion after a function's last line seeds
   `changed_entities=[]` → risk 0.0 → 6/6 dependents missed) and produces
   one context-bleed false positive on a function-boundary case (B5: 3 hunk
   context lines intersect the adjacent function → the seed re-enters via a
   real caller; detected ⊇ expected).* **`compute_blast_radius()` is not the
   limiting mechanism — `seed_entities_for_diff()` is.** C3 (patch corpus)
   independently reproduced the same geometry gap (its C3 case).
2. **Incremental parse tail** (limits criterion 11): *warm median 33 µs
   (proving reparsing IS incremental — cold full parse is 3.7 ms) but the
   <1 ms p95 target fails at 3.8 ms; the tail is edit-position/tree-shape
   dependent (per-edit-line medians span 20 µs…4.3 ms; tree-sitter re-lexes
   to the next change point) and mildly cumulative (31→40 µs across halves);
   p99 is host-unstable at its 5 ms limit — four runs straddled it
   (4.27…6.14 ms, verdict flipping MET/MIS), so a 1000-sample protocol
   cannot establish that boundary on this host.*
3. **Retrieval below both gates** (criteria 3–4): hybrid beats dense-only
   on every frozen-corpus metric but not by the +5 pt margin; recall@5
   0.67 < 0.80. Graph channel excluded from both conditions by protocol
   (stated, not tuned away).
4. **Invariant recall residuals** (criterion 8): two pre-declared misses —
   unquoted secret below the scanner's 12-char floor; graph relative-import
   blindness in `forbid_import`. Scanner frozen; labels were data.
5. **C1's equivalence denominator** (criterion 5): one label miss is
   mechanism 1 (blast tail-insertion hunk shape); the 4/4 semantic
   false-accept is V1's documented scope (provenance+impact, not intent) —
   measured, and the corpus being synthetic stand-ins is stated everywhere it
   appears.

## V1.1 order (evidence-driven)

| Priority | Work | Evidence basis |
|---|---|---|
| 1 | **Diff→entity seeding geometry** | C2 isolated the exact mechanism; B5 + B6 are frozen reproductions. Run as a new frozen experiment: reproduce B5/B6 first, implement candidate fix, require the C2 corpus to show improvement without regression **before** expanding the corpus |
| 2 | **Real LLM patch corpus** | C1's 0.875 is explicitly limited by synthetic stand-ins |
| 3 | **Retrieval judged-set expansion / investigation** | B2 below both gates on the frozen set |
| 4 | **Invariant recall residuals** | 0.889 with two known mechanisms |
| 5 | **Cross-machine parse latency** | decide whether p95 is algorithmic, environmental, or both |

Explicit non-targets, per the measurements: traversal logic and general
detector semantics are **not** identified as limiting mechanisms; no V1.1
effort there until evidence demands it.

## Method (applied identically B1→C3)

corpus construction → ground truth frozen before measurement → baseline
reproduced → single measurement → misses reported, not tuned → source-freeze
proof (git diff + hashes) → opt-in repro guards → thresholds from PLAN.md
never retrofitted. "515 tests pass" is supporting evidence; the conclusion is
this document's measured map of what works, what doesn't, and why.

---

## Addendum — V1 correctness repair campaign (post-baseline)

Everything above this line is the **`v1.0-evidence-baseline` record** and
stays exactly as frozen: the corpora, labels, first-run numbers, and the
"mechanism 1 not repaired" classification are historically reproducible
against tag `v1.0-evidence-baseline`. This addendum records a separate,
later campaign that fixed demonstrated **correctness defects** (not
tuning), and reports the measured deltas honestly. No frozen corpus,
label, or threshold was altered; historical `results.json` files are
byte-unchanged and their guards now dual-pin (historical + post-repair).

Source drift since baseline: yes — this was a correctness campaign, so
`verifyci/` changed (unlike B1→C3, which measured a frozen tree). Each
change is guarded by a failing-first test. See CHANGELOG "A1–A8".

Mechanism-1 (blast seeding geometry) is now **repaired**, and the frozen
corpora re-measured on the repaired code (same cases, same expected
sets):

| Criterion | Baseline (frozen) | Post-repair re-measure | Mechanism |
|---|---|---|---|
| Blast coverage (C2) | 0.8571, B6 gap | **1.0** | A2 insertion-anchor seeding; B6 seeds 2 entities → 6/6 dependents; B5 FP unchanged (disclosed, not tuned) |
| Patch equivalence (C1) | 0.875, C3 miss | **1.0** | A2 closes C3's tail-insertion; all other verdicts bit-identical |
| Verification precision (C1) | 1.0 | 1.0 | unchanged; 4/4 FAILs still truly-wrong |

Classification update: criteria 5 (patch equivalence) and 6 (blast
coverage) move from *measured-unmet* to *measured-met-on-frozen-corpus*.
This is **still not "established"**: the corpora remain the same small
synthetic/curated sets (9 blast cases, 8 correct patches); the gates are
met at a scale too small to establish, exactly as the baseline said.
Mechanisms 2 (incremental p95), 3 (retrieval), 4 (invariant recall) are
**untouched** by this campaign — correctness repairs do not address
them. V1.1 #1 (seeding geometry) is therefore **done**; #2–#5 stand.

New correctness properties established (not previously measured):
- task-scoped chain verification (A1) — 9 focused + integration tests;
- canonical single diff parser with binary/mode visibility (A4) — 19
  tests + a 97-diff golden-snapshot migration proof;
- infrastructure ≠ verdict (A5) — INFRA_ERROR/exit-3 channel, WAL
  concurrency, 18 tests; four V1 verdict states unchanged;
- bitemporal re-ingest integrity (A6) — stamp-preserving upserts;
- repository identity for `.` (A7); platform hardening (A8): .pio skip,
  deterministic utf-8-sig manifest reads, PowerShell UTF-16 diffs,
  recorded corrupt-manifest errors.

P2 (removal provenance) evaluated, NOT implemented: 5.3% of sampled
functions exceed the snippet cap; a fabricated deep-line removal in a
truncated function escapes FAIL (reads unverified → INCONCLUSIVE). That
is consistent with the stated V1 principle "absence of record is not
contradiction" — it is a capability cap, not a broken contract, so
compact per-line hashes stay deferred.

Suite at end of campaign, with patch+blast reruns: **597 passed / 1 skipped**
(default: 595 passed / 3 skipped; 598 collected), ruff clean.
