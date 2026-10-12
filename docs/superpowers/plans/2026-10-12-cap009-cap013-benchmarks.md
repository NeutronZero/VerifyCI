# CAP-009 through CAP-013 Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add five frozen benchmark corpora (CAP-009 diff-to-impact, CAP-010 retrieval generalization, CAP-011 secret held-out, CAP-012 repo performance envelope, CAP-013 differential/mutation) following existing CAP conventions.

**Architecture:** Each CAP is an independent frozen corpus directory with hash-pinned cases/labels, a standalone `measure_cap*.py` harness using clean-room oracles, a thin `tests/evaluation/test_cap*.py` reproduction test, and a `RESULTS.md` adjudicated under the evidence taxonomy in `docs/benchmarks.md:22-30`. Shared conventions are locked in Task 1; CAP tasks consume them.

**Tech Stack:** Python (>=3.12 floor), pytest (`tests/evaluation/`), existing `verifyci` APIs (`seed_entities_for_diff` in `verifyci/verification/diffmap.py:762`, `SecretDetector`, `GraphStore`, `run_verify`), SHA-256 freeze files.

**Spec:** The benchmark audit in conversation (2026-10-12) recommending CAP-009–CAP-013 with workloads, metrics, and acceptance criteria. Key thresholds copied verbatim into each task below. Verified repo facts grounding this plan: CAP layout (`cases.jsonl`, `labels.jsonl`, `config.json`, `CORPUS_SHA256`, `LABEL_SHA256`, `measure_*.py`, `MODE_PROTOCOL.md`, `results.json`, `RESULTS.md`) per `benchmarks/call_semantics_corpus/cap004/`; existing gates in `docs/benchmarks.md:9-18`; repro commands in `docs/benchmarks.md:41-58`.

## Global Constraints

- `requires-python = ">=3.12"` (`pyproject.toml:20`); ty resolves imports against the 3.12 floor — no imports unavailable on 3.12.
- Ruff gate selects `E4,E7,E9,F,B023` (`pyproject.toml:82-86`); every task ends with `ruff check` clean on touched files.
- Frozen means frozen: gold labels sealed before measuring; `config.json` carries `corpus_sha256`, `label_sha256`, `status`, `freeze_rule` (pattern: `benchmarks/call_semantics_corpus/cap004/config.json`).
- Evidence taxonomy (`docs/benchmarks.md:22-30`): report Established / Measured-Met-Not-Established / Measured-Unmet / Unmeasured honestly; never retune a gate to fit results.
- No raw secrets in corpora: CAP-011 positives must be safely synthesized; every measure script asserts zero raw-secret leakage via `assert_no_secret_leak` (`verifyci/secrets/redaction.py:65`).
- No repo dirtying: measure scripts write `results.json` in-corpus (frozen-corpus convention) but performance logs/tmp outputs go to TEMP; restore any file the harness rewrites.
- Corpus case minimums from spec: CAP-009 ≥200 diffs, CAP-010 ≥200 queries / ≥1000 docs / ≥10 repos, CAP-011 held-out set separate from CAP-002B (untouched).
- Ground-truth independence (P0-1): no production implementation (`diffmap` parser/seeder, traversal, detectors) may participate in label/oracle computation. Labels are independently authored artifacts frozen before measurement.
- Adjudication from canonical data (P0-6): eval tests recompute aggregate metrics from per-case/per-query rows and verify case counts, unique ids, and frozen inputs — never just hash + key presence. Results bind implementation commit, clean/dirty worktree state, harness hash, oracle hash, config, and environment. The adjudicator derives verdicts from canonical measurements; a recorded `"PASS"`/`"established": true` field is never trusted.

## Review Focus

- Diff with a rename plus same-basename collision seeds the wrong file's entities; expect correct-file precision, not just any-entity recall (Task 2).
- Retrieval query with no valid relevant result must score zero gracefully, not crash or return junk as relevant (Task 3).
- Secret-adjacent non-secret (documentation placeholder, test fixture) must not flip to FAIL after recall tuning (Task 4).
- CAP-012 large-repo tier must complete inside the predeclared budget on the Windows runner, not just Linux (Task 5).
- A mutation that only relaxes a fail-closed check must be killed even when all hand-authored cases still pass (Task 6).

---

### Task 1: Shared CAP conventions note

**Files:**
- Create: `benchmarks/CAP_CONVENTIONS.md`
- Test: n/a (docs only; verified by reviewer)

**Interfaces:**
- Consumes: existing CAP-004/CAP-002B layouts.
- Produces: directory/file contract every CAP task follows: `cases.jsonl`, `labels.jsonl`, `config.json` (with `experiment_id`, `case_count`, `slice_counts`, `corpus_sha256`, `label_sha256`, `status`, `freeze_rule`), `CORPUS_SHA256`, `LABEL_SHA256`, `author_cap*.py`, `measure_cap*.py` (validates freeze hashes before measuring), `MODE_PROTOCOL.md`, `results.json` (per-case rows + provenance binding: impl commit, worktree state, harness/oracle hashes, config, env), `RESULTS.md`, `tests/evaluation/test_cap*_*.py`.
- Stage gate: this task is Stage 1 — independent review approves the contract before any corpus is created (P0-6: contract mandates per-case recomputation, provenance binding, verdict-from-canonical-data).

- [ ] **Step 1: Write `benchmarks/CAP_CONVENTIONS.md`** naming the required files, the freeze-hash validation order (hashes checked before any measurement), the RESULTS.md sections (gates table with predeclared thresholds, per-slice breakdown, evidence classification per gate), the oracle-independence rule (ground truth authored independently of production code; the oracle's provenance recorded), and the provenance binding every `results.json` carries (implementation commit, clean/dirty worktree, harness hash, oracle hash, config hash, environment).
- [ ] **Step 2: Commit**

```bash
git add benchmarks/CAP_CONVENTIONS.md
git commit -m "docs: record shared frozen-corpus conventions for CAP-009-013"
```

### Task 2: CAP-009 end-to-end diff-to-impact correctness

**Files:**
- Create: `benchmarks/diff_impact_corpus/cap009/` (`cases.jsonl`, `labels.jsonl`, `config.json`, `CORPUS_SHA256`, `LABEL_SHA256`, `author_cap009.py`, `measure_cap009.py`, `MODE_PROTOCOL.md`, `results.json`, `RESULTS.md`)
- Create: `tests/evaluation/test_cap009_repro.py`
- Test: `tests/evaluation/test_cap009_repro.py`

**Interfaces:**
- Consumes: Task 1 contract; `seed_entities_for_diff(files, entities, diff)` (`verifyci/verification/diffmap.py:762`), `parse_diff_files` (`diffmap.py:407`).
- Produces: `measure_cap009.py::main()` exit 0 on frozen corpus; `run_cap009(cases_path, labels_path) -> dict` metrics both the eval test and RESULTS.md consume.

Gates (spec verbatim): zero false passes on critical adversarial cases; ≥95% precision and recall on representative slice; source-diff-to-seed errors reported separately from downstream traversal errors.

Oracle independence (P0-1, mandatory): expected changed entities and impact sets must NOT be derived with the production diff parser, seeder, or traversal. `parse_diff_files()` and any `diffmap` code are production dependencies and must not appear in the ground-truth path. Freeze independently authored source-span annotations + raw diff fixtures + graph edges + expected impact sets before evaluating VerifyCI. The rename-plus-same-basename collision case is a mandatory adversarial test. Stage gate: independent oracle-and-label audit before implementation proceeds.

- [ ] **Step 1: Write failing test `test_cap009_repro.py`** asserting corpus/label SHA-256 pins equal `config.json` values, `run_cap009` returns keys `seed_precision`, `seed_recall`, `impact_precision`, `impact_recall`, `empty_seed_rate`, `fp_impact_rate`, `p95_ms`, aggregates recomputed from per-case rows in `results.json` (not trusted fields), and no import of `verifyci.verification.diffmap` in the label/oracle author path (statically asserted by scanning `author_cap009.py` imports).

```python
def test_cap009_freeze_pins():
    cfg = json.load(open("benchmarks/diff_impact_corpus/cap009/config.json"))
    assert sha256_of("benchmarks/diff_impact_corpus/cap009/cases.jsonl") == cfg["corpus_sha256"]
    assert sha256_of("benchmarks/diff_impact_corpus/cap009/labels.jsonl") == cfg["label_sha256"]
    rows = json.load(open("benchmarks/diff_impact_corpus/cap009/results.json"))["cases"]
    assert len(rows) == cfg["case_count"] and len({r["case_id"] for r in rows}) == cfg["case_count"]
```

- [ ] **Step 2: Run test, expect FAIL** (files do not exist).

Run: `pytest tests/evaluation/test_cap009_repro.py -q`
Expected: FAIL (missing corpus).

- [ ] **Step 3: Author corpus** with `author_cap009.py`: ≥200 labeled diffs covering pure insertions at function boundaries, deletions, multi-hunk, renames, nested scopes, decorators, same-basename collisions, mixed-language files; adversarial critical slice labeled separately. Labels: expected changed-entity ids + expected impact sets, sealed before measurement.
- [ ] **Step 4: Implement `measure_cap009.py`** validating freeze hashes first, then computing seed and impact precision/recall against an independent oracle (not the production seeder's own output), writing `results.json` + `RESULTS.md` with the predeclared gates.
- [ ] **Step 5: Run full check**: `pytest tests/evaluation/test_cap009_repro.py -q` PASS, `ruff check` clean, `ty check verifyci` clean.
- [ ] **Step 6: Commit** corpus + harness + test in one commit.

### Task 3: CAP-010 retrieval generalization and hard negatives

**Files:**
- Create: `benchmarks/retrieval_generalization/cap010/` (same contract as Task 2)
- Create: `tests/evaluation/test_cap010_repro.py`
- Test: `tests/evaluation/test_cap010_repro.py`

**Interfaces:**
- Consumes: Task 1 contract; existing BEIR harness patterns (`tests/evaluation/test_beir_harness.py`, `benchmarks/beir/results.json` schema).
- Produces: `run_cap010(...) -> dict` with `recall_at_5`, `recall_at_20`, `ndcg_at_10`, `mrr`, per-category CIs.

Gates (spec verbatim): preserve Recall@5 ≥ 0.80 and nDCG@10 improvement ≥ 0.05 where applicable; report any failed slice (no averaging it away). Workload: ≥200 human-judged queries, ≥1000 docs/entities, ≥10 repos, whole repos held out of dev; include exact-symbol, paraphrase, rare-identifier, misleading-lexical, multi-hop, and no-relevant-result queries.

No-answer scoring (P0-2, mandatory): a no-relevant-result query has ideal DCG 0, so conventional nDCG is undefined — never assign an arbitrary score. Exclude no-answer queries from the nDCG mean and score abstention behavior separately (`correct_abstention_rate`: fraction of no-answer queries returning zero relevant-claimed results; plus `false_relevant_rate` on that slice). Held-out repos are excluded from development and tuning, but their documents MAY be present in the evaluation search index where the category requires it (record per-category index membership in config). Freeze repository snapshots, model/provider versions, relevance judgments, and per-query-category denominators in `config.json`. Stage gate: separate relevance-label review before measurement.

- [ ] **Step 1: Write failing test** asserting freeze pins + metric keys (`recall_at_5`, `recall_at_20`, `ndcg_at_10`, `mrr`, `correct_abstention_rate`, `false_relevant_rate`) + held-out repo list disjoint from dev repo list in config + per-category denominators in config match labeled query counts + nDCG mean recomputed from per-query rows excluding no-answer queries.
- [ ] **Step 2: Run test, expect FAIL.**
- [ ] **Step 3: Author corpus** (queries, docs, qrels with per-query categories; no-relevant-result queries labeled explicitly).
- [ ] **Step 4: Implement `measure_cap010.py`** (freeze validation first; per-category metrics with confidence intervals; failed slices listed by name in RESULTS.md).
- [ ] **Step 5: Run full check** (pytest PASS, ruff/ty clean).
- [ ] **Step 6: Commit.**

### Task 4: CAP-011 held-out secret detection and redaction safety

**Files:**
- Create: `benchmarks/secret_heldout/cap011/` (same contract)
- Create: `tests/evaluation/test_cap011_repro.py`
- Test: `tests/evaluation/test_cap011_repro.py`

**Interfaces:**
- Consumes: Task 1 contract; `SecretDetector.scan_diff` (`verifyci/secrets/engine.py`), `assert_no_secret_leak` (`verifyci/secrets/redaction.py:65`); CAP-002B corpus stays untouched.
- Produces: `run_cap011(...) -> dict` with `recall`, `recall_by_category`, `precision`, `far`, `frr`, `name_independent_recall`, `redaction_violations`.

Gates (spec verbatim, proposed new gates): ≥95% overall recall, ≥90% name-independent recall, ≥99% precision on the held-out set; zero raw-secret leakage into logs/reports/evidence.

Redaction boundary (P0-3, mandatory): synthetic credential values MUST remain in the frozen input corpus (the detector needs them to be evaluated). The leakage check targets runtime outputs only — serialized results, logs, reports, persisted evidence — never the input fixtures. `measure_cap011.py` scans every serialized output against the known synthetic values from `cases.jsonl` and asserts detection findings carry redacted (never raw) values. CAP-002B files and hashes stay unchanged. Stage gate: secret-handling audit before measurement.

- [ ] **Step 1: Write failing test** asserting freeze pins + metric keys + `redaction_violations == 0` over runtime outputs + CAP-002B files unmodified (compare `benchmarks/secret_corpus/cap002b/` file hashes against recorded pins) + leakage scan explicitly excludes the input `cases.jsonl` path (assert the scanner's target list contains no `cases.jsonl`).
- [ ] **Step 2: Run test, expect FAIL.**
- [ ] **Step 3: Author corpus** (synthesized credentials only; neutral names, provider formats, encoded/fragmented values, connection strings, private keys, doc placeholders, tests, generated files; negatives weighted to placeholders/fixtures).
- [ ] **Step 4: Implement `measure_cap011.py`** (freeze validation first; leakage assertion over every serialized artifact).
- [ ] **Step 5: Run full check** (pytest PASS, ruff/ty clean).
- [ ] **Step 6: Commit.**

### Task 5: CAP-012 end-to-end repository performance envelope

**Files:**
- Create: `benchmarks/repo_perf/cap012/` (`config.json` with workload tiers + budgets, `measure_cap012.py`, `MODE_PROTOCOL.md`, `results.json`, `RESULTS.md`; repos generated/synthetic, not frozen source dumps)
- Create: `tests/evaluation/test_cap012_repro.py`
- Test: `tests/evaluation/test_cap012_repro.py`

**Interfaces:**
- Consumes: Task 1 contract; full pipeline entry points (`run_ingest`, `run_verify`, blast-radius, evidence export).
- Produces: `run_cap012(...) -> dict` with `p50_ms`, `p95_ms`, `p99_ms`, `peak_rss_mb`, `storage_growth_per_rev`, `cache_hit_rate` per tier.

Gates (spec verbatim): tiers and latency/memory budgets declared in `config.json` before measurement; CAP-007 S2 50 ms MISS stays recorded until genuinely met; no whole-system claim from one fast component. Workload: small/medium/large repos × 1/10/100-file commits, cold+warm cache, large diffs, high-fanout graphs, concurrent runs.

Reproducible gates (P1-4, mandatory): hard pass/fail timing gates run ONLY in a pinned benchmark environment (runner spec, OS image, CPU, Python build recorded in `config.json`); on ordinary Windows/Linux CI the eval test asserts functional completion + schema of measurements and REPORTS timings without gating on them. `config.json` declares warm-up runs, repetition count, benchmark ordering (fixed order, caches reset between tiers), process-level peak RSS method, CPU/runtime metadata capture, and the aggregation rule (median across repetitions; p95/p99 reported with repetition count). Never merge Windows and Linux latency distributions. Stage gate: performance-protocol review before the full matrix runs.

- [ ] **Step 1: Write failing test** asserting tier/budget declarations exist in `config.json` and `run_cap012` returns all envelope keys. On non-pinned runners the test asserts functional keys + schema only and skips budget comparison with an explicit `pytest.skip` reason naming the missing pinned-env marker.
- [ ] **Step 2: Run test, expect FAIL.**
- [ ] **Step 3: Implement `measure_cap012.py`** (per-tier timing of ingest→evidence, peak-RSS capture, results split by OS without merging latency distributions).
- [ ] **Step 4: Record results** into `results.json`/`RESULTS.md` with budgets-vs-measured table.
- [ ] **Step 5: Run full check** (pytest PASS, ruff/ty clean; note: full-measure run is slow — eval test asserts on recorded `results.json` + a smoke tier, not the full matrix).
- [ ] **Step 6: Commit.**

### Task 6: CAP-013 differential, property-based, and mutation benchmark

**Files:**
- Create: `benchmarks/robustness/cap013/` (`generators.py` seeded topology/diff/call-arg/history fuzzers, `mutations.py` fault injectors, `measure_cap013.py`, `MODE_PROTOCOL.md`, `results.json`, `RESULTS.md`, `config.json` with stored seeds)
- Create: `tests/evaluation/test_cap013_repro.py`
- Test: `tests/evaluation/test_cap013_repro.py`

**Interfaces:**
- Consumes: Task 1 contract; equivalence-test patterns (`tests/evaluation/test_optimizations_equivalence.py`); production checkers under test.
- Produces: `run_cap013(seed) -> dict` with `oracle_disagreement_rate`, `incorrect_pass_rate`, `mutation_kill_rate`, `false_decline_rate`; deterministic given seed.

Gates (spec verbatim): zero incorrect PASS on critical security/provenance invariants; 100% detection of declared critical mutations; reproducible from stored seeds; stable core suite runs on PRs, larger randomized suite on schedule.

Mutation accounting (P1-5, mandatory): every source mutation executes in an isolated temporary worktree or copy — never the shared checkout. `results.json` carries per-mutation evidence rows: mutation id, what was applied (file + diff), test outcome, and classification `killed` / `survived` / `equivalent`. The 100% kill gate applies to the PREDECLARED set of valid non-equivalent critical mutations in `config.json`; equivalent mutations are classified, not silently dropped. Survivors are recorded explicitly in RESULTS.md with owner follow-up. Stage gate: mutation-accounting review before the gate is claimed.

- [ ] **Step 1: Write failing test** asserting fixed-seed determinism (two runs, identical metrics) + metric keys + every mutation row in `results.json` carries `applied_evidence` and a classification in {killed, survived, equivalent} + kill-rate recomputed from rows over the predeclared non-equivalent set.
- [ ] **Step 2: Run test, expect FAIL.**
- [ ] **Step 3: Implement generators + mutations** (topologies, diff layouts, arg mappings, temporal histories, malformed evidence, resource exhaustion; mutations: edge-direction flip, missing lineage link, altered arg value, path collision, relaxed fail-closed check).
- [ ] **Step 4: Implement `measure_cap013.py`** with critical-mutation kill table and incorrect-PASS list (must be empty for PASS).
- [ ] **Step 5: Run full check** (pytest PASS, ruff/ty clean).
- [ ] **Step 6: Commit.**

### Task 7: Inventory, CI wiring, evidence adjudication

**Files:**
- Modify: `docs/benchmarks.md` (catalog table + repro commands)
- Modify: `.github/workflows/benchmarks.yml` (add CAP-009–013 repro entries)
- Modify: `scripts/adjudicate_performance_evidence.py` if it enumerates suites (check first; skip if generic)

**Interfaces:**
- Consumes: RESULTS.md gate tables from Tasks 2–6.
- Produces: catalog rows for CAP-009–013 with digest prefixes + case counts; CI entries with explicit repro commands; adjudicator that recomputes every verdict from canonical per-case measurements + provenance binding and fails closed on any mismatch (P1-6).

- [ ] **Step 1: Add catalog rows** to `docs/benchmarks.md:9-18` table for CAP-009–013 (digest prefix, cases, scope one-liners) plus missing CAP-002B/003A/004/005 rows per audit §4.
- [ ] **Step 2: Extend `benchmarks.yml`** with one step per CAP pointing at its measure script + eval test; keep manual-dispatch trigger. CAP-012's hard-gate step is conditioned on the pinned-env marker; default CI runs its functional/report-only mode.
- [ ] **Step 3: Harden `scripts/adjudicate_performance_evidence.py`** (or add `scripts/adjudicate_cap.py` if the existing script is suite-specific): verdicts computed from canonical per-case rows + provenance binding (impl commit, worktree state, harness/oracle/config hashes, env); any recorded `"PASS"`/`"established"` field is cross-checked, never trusted; mismatch → adjudication FAIL.
- [ ] **Step 4: Run `pytest tests/evaluation/ -q`** (all CAP repro tests green together) and `ruff check`.
- [ ] **Step 5: Commit.**

## Execution Stages (per approval)

| Stage | Work | Review gate |
| ----- | ---- | ----------- |
| 1 | Task 1 conventions + evidence contract | Approve contract before corpora |
| 2 | Task 2 CAP-009 | Oracle-and-label audit before proceeding |
| 3 | Tasks 3–4 CAP-010/011 | Relevance-label review + secret-handling audit |
| 4 | Tasks 5–6 CAP-012/013 | Performance-protocol + mutation-accounting reviews |
| 5 | Task 7 CI/docs/adjudication | Full-branch review, regression tests, hash verification |

## Self-Review

1. Spec coverage: audit §3 items → Tasks 2–6 one-to-one; §4 inventory → Task 7 docs step; §4 cross-platform/repeatability/regression/resource/evidence rules → embedded as Task 5 OS-split + Task 6 seeds + Task 1 freeze-first + Task 7 adjudication. Secret-workload vs measured-case reconciliation (audit §2) → Task 4 owns corpus definition; add Task 5 note? Covered: Task 5 config declares workloads before measuring.
2. Step scan: each step names one artifact + checkable command; fixed by keeping code bodies out (only test sketches where the spec pins values).
3. Type consistency: `run_cap00X` return-key names defined once per task and reused in that task's test step; cross-task names intentionally independent (separate corpora).
4. Review Focus: five lines above, each mapped to its owning task in parentheses.
5. Proportion: plan states decisions (paths, gates, keys, order); implementer writes bodies. No transcripts.
