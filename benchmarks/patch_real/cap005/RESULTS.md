# CAP-005 Benchmark Results: Generalization & Real-World Patch Validation

**Experiment ID**: CAP-005  
**Decision**: **PROMOTE**  
**Status**: **ESTABLISHED**  
**Scope**: Frozen 64-case authentic multi-repository patch corpus.  
**Corpus Hash**: `ca475b33a385e8d1478afedf00d2eeeefdc8ae0f72c9e5527f20fc1fe814e17c`  
**Label Hash**: `589231d38fdf85a764eab85ba19f1ad9e2839fe63c043c3c9636d745f1893075`  
**Source Hash**: `f330fca7d317ec9a1e8398295d930c49f802e2cc25cf94b3906d7b9b0d47af8d`  
**Harness Hash**: `8e8874bea2c45fc941472a921b0c24329e0053fb47f95b68279fdd05a172ef4f`  
**Results Hash**: `e7ed2033774e27646232eb8e9ce82b0ee891186acfb35cd2f6529e74fa0133ba`  

## Executive Summary
VerifyCI demonstrates robust generalization on the frozen 64-case authentic multi-repository CAP-005 corpus, achieving an overall agreement of **62/64 (96.88%)** across 5 permissive open-source repositories and agent session logs.

Crucially:
- **Zero false acceptance observed on the 24 pre-labeled violation cases in the frozen CAP-005 corpus** (Security FAR = 0.0000).
- **Zero false confidence observed on ungrounded/inconclusive cases** (FCR = 0.0000).
- **All 9 pre-labeled falsifier cases were rediscovered with 100% recall** across secrets, removals, and call semantics.

## Evidence Scope & Epistemic Boundaries
- **What is established**: Integrated VerifyCI behavior on this corpus, including security fail-closed behavior, falsifier rediscovery, call-semantic escalation, removal provenance handling, multi-file routing, dynamic-code epistemic boundaries, latency, infrastructure stability, and clean-room/non-regression state.
- **What remains unestablished**: Universal real-world generalization, population-wide FAR/FCR, and completeness outside the frozen corpus.

## Acceptance Predicates (P1–P10)

| Predicate | Target | Measured | Result | Status |
|---|---|---|---|:---:|
| **P1: Overall Agreement** | $\ge 0.9000$ | **0.9688** (62/64) | **PASS** | Established |
| **P2: False Acceptance Rate (FAR)** | $0.0000$ | **0.0000** (0/24) | **PASS** | Established |
| **P3: False Confidence Rate (FCR)** | $0.0000$ | **0.0000** (0/2) | **PASS** | Established |
| **P4: Violation Detection Recall** | $1.0000$ | **1.0000** (24/24) | **PASS** | Established |
| **P5: Falsifier Rediscovery Recall** | $1.0000$ (9/9) | **1.0000** (9/9) | **PASS** | Established |
| **P6: Compliant Verification Recall** | $\ge 0.9000$ | **0.9474** (36/38) | **PASS** | Established |
| **P7: Latency p95** | $\le 500\text{ms}$ | **23.5ms** (p50=18.2ms, max=135.3ms) | **PASS** | Established |
| **P8: Zero Infrastructure Crashes** | $0$ crashes | **0** crashes | **PASS** | Established |
| **P9: Multi-Repo License Provenance** | $5/5$ permissive | **5/5** audited | **PASS** | Established |
| **P10: Clean-Room Non-Regression** | 0 regressions | attested, see CI | **PASS** | Established |

## Confusion Matrix

| Expected \ Predicted | PASS | FAIL | HUMAN_REVIEW | INCONCLUSIVE | INFRA_ERROR | Total |
|---|---:|---:|---:|---:|---:|---:|
| **PASS** | **36** | 0 | 0 | 2 | 0 | 38 |
| **FAIL** | 0 | **9** | 0 | 0 | 0 | 9 |
| **HUMAN_REVIEW** | 0 | 0 | **15** | 0 | 0 | 15 |
| **INCONCLUSIVE** | 0 | 0 | 0 | **2** | 0 | 2 |

### Characterization of Inconclusive Outcomes (Safe Incompleteness)
The two non-matching predictions (`REAL-REM-02` and `REAL-REM-04`) in `production_code_removals` (6/8 = 75.00% agreement) are conservative `PASS -> INCONCLUSIVE` outcomes.
Because deleted code was outside indexed entity spans, the system declined to assert truth rather than inventing provenance.
They are permanently recorded as **safe incompleteness**—sacrificing completeness rather than verification integrity—in accordance with Contract 3.

## Stratified Slices Breakdown

| Slice | Cases | Correct | Agreement |
|---|---:|---:|---:|
| `agent_generated_hallucinations` | 8 | 8 | 100.00% |
| `authentic_security_patches` | 8 | 8 | 100.00% |
| `call_site_and_signature_evolution` | 8 | 8 | 100.00% |
| `complex_composite_diffs` | 8 | 8 | 100.00% |
| `dynamic_runtime_idioms` | 8 | 8 | 100.00% |
| `manifests_and_documentation` | 8 | 8 | 100.00% |
| `multi_file_feature_additions` | 8 | 8 | 100.00% |
| `production_code_removals` | 8 | 6 | 75.00% |

## Pre-labeled Falsifier Denominator Audit (Lock 3)

| Case ID | Falsifier Class | Gold | Predicted | Matched | Rationale |
|---|---|---|---|:---:|---|
| `REAL-SEC-03` | `secret_name_independence` | `FAIL` | `FAIL` | PASS | blocking_check_failed |
| `REAL-SEC-05` | `secret_name_independence` | `FAIL` | `FAIL` | PASS | blocking_check_failed |
| `REAL-SEC-08` | `secret_name_independence` | `FAIL` | `FAIL` | PASS | blocking_check_failed |
| `REAL-REM-03` | `removal_provenance` | `FAIL` | `FAIL` | PASS | blocking_check_failed |
| `REAL-REM-05` | `removal_provenance` | `INCONCLUSIVE` | `INCONCLUSIVE` | PASS | checks_ran_but_nothing_established |
| `REAL-REM-07` | `removal_provenance` | `PASS` | `PASS` | PASS | all_checks_passed_behavior_not_verified |
| `REAL-CALL-02` | `argument_value_blindness` | `HUMAN_REVIEW` | `HUMAN_REVIEW` | PASS | non_blocking_failures |
| `REAL-CALL-04` | `argument_value_blindness` | `HUMAN_REVIEW` | `HUMAN_REVIEW` | PASS | non_blocking_failures |
| `REAL-CALL-06` | `argument_value_blindness` | `HUMAN_REVIEW` | `HUMAN_REVIEW` | PASS | non_blocking_failures |
