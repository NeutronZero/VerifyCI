# CAP-004 Benchmark Results: Call-Semantics & Argument-Value Verification

## 1. Cryptographic Freeze Coordinates
- **Experiment ID**: `CAP-004`
- **Corpus SHA-256**: `305da66ef4282c7537d9d0366f5d6726acb2b5557114823298e053dbf038c064`
- **Labels SHA-256**: `1733902248e7bc4dcad51c01ffe6e10e362f1a34e899317f958aa4d04d95ab59`
- **Total Cases**: 36
- **Distribution**: 13 VERIFIED, 13 FAIL, 10 INCONCLUSIVE

## 2. Comparative Evaluation Summary

| Metric | C0 (Legacy Argument-Blind) | C1 (Call-Semantics Engine) | Target Gate Predicate | Status |
|---|---:|---:|---:|---|
| **Overall Agreement** | 0.3611 (13/36) | **1.0000** (36/36) | ≥ 0.9500 | **MET** |
| **False Acceptance Rate (FAR)** | 1.0000 | **0.0000** | = 0.0000 | **MET** |
| **False Confidence Rate (FCR)** | 1.0000 | **0.0000** | = 0.0000 | **MET** |
| **Violation Detection Recall** | 0.0000 | **1.0000** | = 1.0000 | **MET** |
| **Compliant Verification Recall** | 1.0000 | **1.0000** | = 1.0000 | **MET** |
| **Dynamic Inconclusive Recall** | 0.0000 | **1.0000** | = 1.0000 | **MET** |

## 3. Slice Breakdown

| Slice | Cases | C0 Agreement | C1 Agreement | Resolution |
|---|---:|---:|---:|---|
| `keyword_argument_values` | 5 | 2/5 (0.40) | **5/5** (1.00) | RESOLVED |
| `positional_argument_values` | 5 | 2/5 (0.40) | **5/5** (1.00) | RESOLVED |
| `argument_order_swap` | 4 | 2/4 (0.50) | **4/4** (1.00) | RESOLVED |
| `dynamic_expression_args` | 5 | 1/5 (0.20) | **5/5** (1.00) | RESOLVED |
| `kwargs_unpacking` | 4 | 1/4 (0.25) | **4/4** (1.00) | RESOLVED |
| `default_arg_reliance` | 4 | 2/4 (0.50) | **4/4** (1.00) | RESOLVED |
| `overload_receiver_context` | 4 | 2/4 (0.50) | **4/4** (1.00) | RESOLVED |
| `call_routing_mutation` | 5 | 1/5 (0.20) | **5/5** (1.00) | RESOLVED |

## 4. Decisive Engineering Results & Falsifier Resolution

### A. Resolution of CAP-002 N-S4 Falsifier (`CALL-MUT-01`)
- **Historical Defect**: In CAP-002, held-out case `N-S4` (`send_email('a')` -> `send_email('b')`) passed silently because legacy checks inspected only callee node names and LHS assignment disappearance. Argument-value changes were completely invisible.
- **C0 Result**: `VERIFIED` (False Acceptance). C0 observed `send_email` referenced and passed the diff.
- **C1 Result**: Violation detected (`call argument string literal mutated from 'a' to 'b'`).
- **Policy Routing Distinction**: Detected argument-semantic violations never produced PASS. Policy routing escalates them to `HUMAN_REVIEW` under the default non-blocking call-semantics contract (or `FAIL` under blocking invariant contracts), preserving the invariant that absence of verified intent never produces a silent pass.

### B. Epistemic Invariant: Absence of Proof is Not Proof of Compliance
- Across all 10 ungrounded dynamic cases (`os.environ.get`, `session.method()`, variable `**kwargs` / `*args`, unmodeled signatures), C0 falsely accepted them as `VERIFIED` with false confidence.
- C1 deterministically routed 10/10 (100%) to `INCONCLUSIVE`, guaranteeing 0 observed false confidence.

### C. Constant Folding & Expression Safety
- C1 folded compile-time constant binary operations (`'AES' + '-GCM'`, `100 * 1000`) deterministically without using forbidden `eval()`.
- C1 detected conditional expressions permitting forbidden branches (`allow_builtins=True if debug else False`) and routed them to `FAIL`.

## 5. Adjudication Predicates Matrix
- **Corpus & Labels Frozen**: PASS
- **False Acceptance Rate = 0.0000**: PASS (0/13 violations accepted)
- **False Confidence Rate = 0.0000**: PASS (0/10 ungrounded cases falsely verified)
- **Violation Detection Recall = 1.0000**: PASS (13/13 violations detected)
- **Compliant Verification Recall = 1.0000**: PASS (13/13 verified)
- **Dynamic Inconclusive Recall = 1.0000**: PASS (10/10 inconclusive)
- **Policy Routing Safety**: PASS (Detected argument-semantic violations never produce PASS; default non-blocking tripwire escalates to HUMAN_REVIEW)
- **Full Pytest Suite**: PASS (1084 passed, 6 skipped, 0 failed)
- **Ruff Clean**: PASS (All checks passed)
- **Adjudication Decision**: **PROMOTE — ESTABLISHED**
