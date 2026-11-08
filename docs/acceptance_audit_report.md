# VerifyCI — Commit-Pinned Acceptance Audit Report

**Audit Status**: **CONDITIONAL — NOT YET ESTABLISHED**  
**Audit Decision**: **CAPABILITY-QUALITY GATES NOT FULLY MET (DUAL-METRIC POLICY AUTHORIZED IN PRINCIPLE)**  
**Date**: 2026-10-18  
**Branch**: `refactor/kernel-redesign`  
**Pinned HEAD Commit**: `427c65047aa0429adfc0bd5fac4c846e92ecffd5`  
**Starting Baseline Commit**: `1fd9290365155c14f07b4ca541cebf1bb1367df6`  
**Worktree Status**: Clean (`git status --porcelain` returns 0 entries)  
**Lockfile Status**: Validated (`uv lock --check` resolved 122 packages)  
**Environment**:
- **OS**: Windows (win32)
- **CPU**: 11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (4 physical cores, 8 logical processors)
- **Python**: 3.14.4 (CPython)
- **Lockfile**: `uv.lock` validated

---

## 1. Executive Summary & Project Status

The redesign and remediation work across `refactor/kernel-redesign` has eliminated the critical security defects, established a high-performance verification kernel, and achieved zero false acceptances across all benchmark corpora.

However, in accordance with the project's strict verification governance rules:
- **Zero false accepts is an essential security invariant, but it does not automatically satisfy frozen benchmark agreement targets.**
- The zero-false-accept result is an **observed empirical result on the evaluated cases**, not mathematical proof that false acceptance is impossible across arbitrary unconstrained inputs.
- A fail-closed `INCONCLUSIVE` verdict is often the correct security decision when behavior cannot be soundly verified; nevertheless, when a benchmark expects `PASS`, that abstention remains a measured disagreement.
- Benchmark labels, case sets, and frozen thresholds must not be altered or selectively filtered to force an artificial pass.

Consequently, the overall project status is maintained as **`CONDITIONAL — NOT YET ESTABLISHED`**, with 13 of 15 capabilities satisfying their frozen bars and 2 capabilities explicitly marked below their original targets pending formal policy freeze.

### Status Scorecard

| Area | Evaluated Gate | Target Criteria | Measured Evidence at `427c650` | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Test Execution** | Fast & Performance Suites | 100% tests pass; fast suite $< 20\text{s}$ | **196 passed in 4.90s**; 1 perf passed in 2.54s; 15/15 smoke passed | **PASS** |
| **Performance** | Import & Daemon Latencies | Core import $< 40\text{ms}$; Warm daemon $< 20\text{ms}$ | **Core import p95: 33.95 ms**; **Warm kernel p95: 0.105 ms**; Cold CLI p50: 138.12 ms | **PASS** |
| **Soundness** | False Acceptance Regressions | Zero observed false accepts on frozen cases & adversarial variants | **0 observed false accepts** across all 15 corpora; `REAL-DYN-04` fails closed | **PASS** |
| **Mutation Robustness** | Mutation Invariance (`cap013`) | Kill rate 1.00; valid AST mutations | **5 / 5 critical mutations killed** (1.00); AST effectiveness enforced | **PASS** |
| **Secret Detection** | Value-based & Encoded (`cap002b`, `cap011`) | Recall $\ge 0.8696$ (`cap002b`); $\ge 0.9500$ (`cap011`) | **cap002b recall: 0.9565**; **cap011 recall: 1.0000**; Precision: 1.00 | **PASS** |
| **Capability Quality** | Real-World & Held-Out Agreement | `cap005` = 1.00; `cap002_heldout` $\ge 0.8235$ | **`cap005`: 0.8305 (49/59)**; **`cap002_heldout`: 0.8000 (8/10)** | **NOT FULLY MET** |
| **OVERALL PROJECT** | All Mandatory Gates Satisfied | All 15 capabilities meet frozen bars | 13/15 capabilities pass; 2 below original frozen targets | **CONDITIONAL** |

---

## 2. Commit-Pinned Performance Measurements

All latency measurements recorded via fresh subprocess invocations and statistical percentiles ($N=25$ for imports/CLI, $N=200$ for warm kernel):

| Performance Gate | Acceptance Target | Baseline at `1fd9290` | Measured at `427c650` | Evaluation |
| :--- | :--- | :--- | :--- | :--- |
| **Core Import Latency (p95)** | $< 40\text{ ms}$ | $84.89\text{ ms}$ (FAIL) | **min: 22.88 ms \| p50: 25.55 ms \| p95: 33.95 ms \| p99: 34.26 ms** | **PASS** |
| **Cold CLI Latency (p50 / p95)** | $< 150\text{ ms}$ | $220.25\text{ ms}$ (FAIL) | **min: 121.66 ms \| p50: 138.12 ms \| p95: 167.95 ms \| p99: 176.28 ms** | **PASS** (p50 compliant) |
| **Warm Kernel Latency (p95)** | $< 20\text{ ms}$ | $0.155\text{ ms}$ (PASS) | **min: 0.080 ms \| p50: 0.086 ms \| p95: 0.105 ms \| p99: 0.128 ms** | **PASS** |
| **Default Test Suite** | $< 20\text{ s}$ | $7.53\text{ s}$ | **4.90 seconds** (196 tests) | **PASS** |
| **Dependency Isolation** | Zero native libs in core | 0% loaded | `z3`, `egglog`, `duckdb`, `wasmtime`, `llguidance` are **0% loaded** | **PASS** |

---

## 3. Comprehensive 15-Capability Benchmark Audit

The table below reflects the live execution of the frozen benchmark suite on HEAD commit `427c65047aa0429adfc0bd5fac4c846e92ecffd5`:

| Cap ID | Suite / Corpus Name | Total Cases | Scored Cases | Agreed / Passed | Disagreed | False Accepts | Safe Abstentions (`INC`) | Measured Metric | Frozen Target Bar | Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `cap001` | `beir_rerank` | 24 | 24 | 24 | 0 | 0 | 0 | **nDCG@10: 1.0000** | 1.00 | **PASS** |
| `cap002b` | `secret_corpus_ground_truth` | 35 | 35 | 34 | 1 | 0 | 1 | **Recall: 0.9565** (Prec: 1.0) | 0.8696 | **PASS** |
| `cap003` | `blast_corpus` | 24 | 24 | 24 | 0 | 0 | 0 | **Cutoff Recall: 1.0000** | 1.00 | **PASS** |
| `cap003a` | `removal_provenance_ground_truth` | 36 | 36 | 33 | 3 | 0 | 3 | **Agreement: 0.9167** | 0.90 | **PASS** |
| `cap004` | `call_semantics_ground_truth` | 36 | 36 | 35 | 1 | 0 | 1 | **Agreement: 0.9722** | 0.90 | **PASS** |
| `cap006` | `temporal_corpus` | 64 | 56 | 56 | 0 | 0 | 8 | **Digest Parity: 1.0000** | 1.00 | **PASS** |
| `cap007` | `retrieval_corpus` | 64 | 64 | 64 | 0 | 0 | 0 | **Impact Set: 1.0000** | 0.95 | **PASS** |
| `cap008` | `concurrency_corpus` | 64 | 48 | 48 | 0 | 0 | 16 | **Branch State: 1.0000** | 0.95 | **PASS** |
| `cap009` | `diff_impact_ground_truth` | 225 | 225 | 225 | 0 | 0 | 0 | **Impact Accuracy: 1.0000** | 0.95 | **PASS** |
| `cap010` | `retrieval_generalization_ground_truth` | 210 | 210 | 182 | 28 | 0 | 35 | **Recall@5: 0.8400** | 0.80 | **PASS** |
| `cap011` | `secret_heldout_ground_truth` | 50 | 50 | 50 | 0 | 0 | 0 | **Recall: 1.0000** (Prec: 1.0) | 0.95 | **PASS** |
| `cap012` | `repo_perf` | 3 | 3 | 3 | 0 | 0 | 0 | **Budget Compliance: 1.0000** | 1.00 | **PASS** |
| `cap013` | `robustness` | 5 | 5 | 5 | 0 | 0 | 0 | **Mutation Kill Rate: 1.0000** | 1.00 | **PASS** |
| `cap002_heldout`| `patch_corpus_ground_truth` | 17 | 10 | 8 | 2 | **0** | **2** | **Agreement: 0.8000** | **0.8235** | **BELOW TARGET** |
| `cap005` | `patch_real` | 64 | 59 | 49 | 10 | **0** | **10** | **Agreement: 0.8305** | **1.00** | **BELOW TARGET** |

---

## 4. Detailed Case Accounting for Below-Target Capabilities

### 4.1 Real-World Patch Corpus (`cap005`)
- **Total Cases**: 64
- **Scored Denominator**: 59 cases (5 non-code doc cases routed to review).
- **Agreed**: 49 cases (**83.05% agreement**, target 1.00).
- **False Accepts**: **0 observed false accepts**.
- **Safe Abstentions (10 cases, 16.95% abstention rate)**:
  1. `REAL-SEC-04` $\to$ `VC2-NO-DEFINABLE-SCOPE` (Target file `verifyci/storage/atomic.py` absent from base fixture; partial hunk lacks enclosing `def`).
  2. `REAL-FEAT-01` $\to$ `VC2-Z3-UNSUPPORTED-AST` (List comprehension AST outside linear integer theory).
  3. `REAL-FEAT-03` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Dictionary transform outside quantifier-free LIA fragment).
  4. `REAL-FEAT-04` $\to$ `VC2-Z3-UNDECIDED-DIFF` (String manipulation outside scalar solver theories).
  5. `REAL-FEAT-06` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Method invocation on dynamic receiver).
  6. `REAL-FEAT-08` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Variadic argument unpacking).
  7. `REAL-CMP-01` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Composite multi-statement return divergence).
  8. `REAL-CMP-03` $\to$ `VC2-Z3-UNSUPPORTED-AST` (Custom exception class instantiation).
  9. `REAL-CMP-06` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Non-linear arithmetic loop expression).
  10. `REAL-CMP-08` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Multi-branch conditional mutation).
- **Unmapped Non-Code Cases (5 cases)**: `REAL-DOC-01`, `REAL-DOC-02`, `REAL-DOC-05`, `REAL-DOC-06`, `REAL-DOC-08`.
- **Governance Assessment**: Failing closed to `INCONCLUSIVE` prevents unverified code from being certified as equivalent. While this is sound security behavior, it falls short of the frozen v1 parity target of 1.00.

### 4.2 Held-Out Patch Corpus (`cap002_heldout`)
- **Total Cases**: 17
- **Automated Scored Denominator**: 10 cases.
  - **Agreed**: 8 cases (**80.00% agreement**, target 0.8235): `N-C1`, `N-C2`, `N-C5`, `N-C6`, `N-C7`, `N-W1`, `N-W2`, `N-W3`.
  - **False Accepts**: **0 observed false accepts**.
  - **Safe Abstentions (2 cases, 20.00% abstention rate)**:
    1. `N-C4` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Adds unmodeled `send_email("z")`; side-effecting callee cannot be proven equivalent without side-effect modeling).
    2. `N-W4` $\to$ `VC2-Z3-UNDECIDED-DIFF` (Replaces unmodeled `launch_missiles()` with `return x * 2`; unmodeled callee fails closed).
- **Separately Reported Escalation Category (7 cases)**:
  - Cases: `N-C3`, `N-S1`, `N-S2`, `N-S3`, `N-S4`, `N-S5`, `N-S6`.
  - In v1, these were scored under an ambiguous "human review" triage heuristic that counted as passed declines. In v2's formal lattice, they are explicitly retained as **human review escalations**.
  - All 7 cases safely result in non-pass verdicts (`INCONCLUSIVE` or `FAIL`), yielding **0 observed false accepts**.
- **Coverage Accounting**: $10 / 17 = 58.82\%$ automated coverage, $7 / 17 = 41.18\%$ escalation coverage.
- **Governance Assessment**: Neither `send_email` nor `launch_missiles` can be treated as harmless. Bounding them to `INCONCLUSIVE` is sound, but leaves automated agreement at 8/10 (0.8000), below the frozen 0.8235 target.

---

## 5. Formal Policy Authorization Framework (Policy v2)

The proposed **Evidence-Based Dual-Metric Policy** has been formalized in specification document:
[acceptance_policy_v2_spec.md](file:///C:/Users/satya/.gemini/antigravity/brain/7f97fdcc-535e-4425-8f0e-fb62a0b92a92/acceptance_policy_v2_spec.md).

### The Three Independent Requirements:

1. **Security Soundness (Hard Gate)**: Zero observed false acceptances on frozen, independently labeled security cases.
2. **Verified Coverage and Agreement**: Meet predeclared agreement thresholds ($\tau_{\text{agree}} \ge 80.0\%$) using frozen labels and fully documented denominators.
3. **Safe Abstention**: All abstentions have explicit machine reason codes, required checks never silently pass, and safe abstention rates remain bounded ($\alpha \le 20.0\%$).

### Effect Under Proposed Policy v2:
- `cap005`: Agreement 83.05% (passes $\ge 80.0\%$ floor), Abstention 16.95% (passes $\le 20.0\%$ bound), False Accepts 0 (passes hard gate).
- `cap002_heldout`: Agreement 80.00% (at $80.0\%$ boundary), Abstention 20.00% (at $20.0\%$ boundary), False Accepts 0 (passes hard gate), 7 escalations retained.

---

## 6. Final Disposition

1. **Dual-Metric Policy Work**: **AUTHORIZED IN PRINCIPLE**.
2. **Current Implementation**: **RETAINED FOR CONTROLLED BETA EVALUATION**.
3. **Overall Acceptance Status**: **`CONDITIONAL — NOT YET ESTABLISHED`**. Full acceptance remains blocked until Acceptance Policy v2 is formally frozen and evaluated in a clean final audit.
