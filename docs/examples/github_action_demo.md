# VerifyCI-Demo: GitHub Action Integration Plan

This document outlines the reference demonstration repository (`VerifyCI-Demo`) and live test matrix for validating the VerifyCI GitHub Composite Action (`uses: NeutronZero/VerifyCI@v0.1.0`) in real GitHub pull requests.

---

## 1. Demo Repository Layout

A minimal, independent public repository structure:

```text
VerifyCI-Demo/
├── .github/
│   └── workflows/
│       └── verifyci.yml          # Verification gate workflow
├── .verifyci/
│   └── invariants.yaml           # Repository-level safety rules
├── pyproject.toml                # Standard Python package metadata
├── src/
│   └── service.py                # Core application module
└── tests/
    └── test_service.py           # Unit tests
```

### A. Workflow Configuration (`.github/workflows/verifyci.yml`)

```yaml
name: VerifyCI Verification Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  verify:
    name: Verify PR Diff
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      # Execute VerifyCI Composite Action
      - name: Run VerifyCI Gate
        uses: NeutronZero/VerifyCI@v0.1.0
        id: verifyci
        with:
          format: sarif
          output-file: verifyci-results.sarif

      # Upload SARIF findings to GitHub Security Tab
      - name: Upload Findings to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: verifyci-results.sarif
```

### B. Invariant Definition (`.verifyci/invariants.yaml`)

```yaml
invariants:
  - id: forbid_dynamic_eval
    rule: "Disallow dynamic eval calls in application services"
    query: "forbid_call:eval"
    blocking: true

  - id: forbid_insecure_protocols
    rule: "Disallow legacy telnet protocol imports"
    query: "forbid_import:telnetlib"
    blocking: true
```

---

## 2. Integration Test Matrix (5 Canonical Cases)

| Test Case | Scenario | PR Modification | Expected Verdict | Action Exit Code | GitHub Check Status | SARIF Level |
|---|---|---|:---:|:---:|:---:|:---:|
| **Case A** | Clean Feature Addition | Add helper calling existing entity | `PASS` | `0` | Success (Green) | 0 results |
| **Case B** | Invariant Violation | Introduce `eval(...)` call | `FAIL` | `1` | Failure (Red) | `error` (`fail`) |
| **Case C** | Policy Tampering / Uncertainty | Modify `.verifyci/invariants.yaml` | `HUMAN_REVIEW` | `2` | Failure (Fail-Closed) | `warning` (`review`) |
| **Case D** | Hardcoded Secret Injection | Add high-entropy token in diff | `FAIL` | `1` | Failure (Red, 0 Leaks) | `error` (Redacted) |
| **Case E** | Infrastructure / Storage Failure | Invalid database path or unreadable store | `INFRA_ERROR` | `3` | Failure (Fail-Closed) | Execution alert |

---

## 3. Case Details & Pull Request Diffs

### Case A: Clean Feature Addition (Expected: PASS, Exit 0)
- **Diff**:
  ```diff
  --- a/src/service.py
  +++ b/src/service.py
  @@ -10,3 +10,6 @@ def calculate_total(price, qty):
       return price * qty
  +
  +def apply_standard_discount(price, qty):
  +    return calculate_total(price, qty) * 0.95
  ```
- **Validation**:
  - `status`: `PASS`
  - `rationale`: `all_checks_passed_behavior_not_verified`
  - Exit code: `0`
  - Action concludes successfully, allowing PR merge.

### Case B: Blocking Invariant Violation (Expected: FAIL, Exit 1)
- **Diff**:
  ```diff
  --- a/src/service.py
  +++ b/src/service.py
  @@ -2,1 +2,1 @@ def calculate_total(price, qty):
  -    return price * qty
  +    return eval("price * qty")
  ```
- **Validation**:
  - `status`: `FAIL`
  - `rationale`: `blocking_check_failed`
  - Exit code: `1`
  - Action fails closed, posting error finding to GitHub Code Scanning.

### Case C: Policy Tampering (Expected: HUMAN_REVIEW, Exit 2 / Fail-Closed)
- **Diff**:
  ```diff
  --- a/.verifyci/invariants.yaml
  +++ b/.verifyci/invariants.yaml
  @@ -4,1 +4,1 @@ invariants:
  -    blocking: true
  +    blocking: false
  ```
- **Validation**:
  - `status`: `HUMAN_REVIEW`
  - `rationale`: `unverified_policy_change: gate configuration modified in diff`
  - Exit code: `2`
  - With default `fail-on-inconclusive: true`, the action step fails closed (red check). PR requires human reviewer intervention.

### Case D: Secret Injection (Expected: FAIL, Exit 1, Zero Leaks)
- **Diff**:
  ```diff
  --- a/src/service.py
  +++ b/src/service.py
  @@ -1,1 +1,2 @@
  +AUTH_KEY = "sk_test_99887766554433221100aabbccdd"
   def calculate_total(price, qty):
  ```
- **Validation**:
  - `status`: `FAIL`
  - `rationale`: `blocking_check_failed`
  - Exit code: `1`
  - Secret token `sk_test_9988...` is strictly redacted with `[REDACTED:entropy]` in SARIF output, log annotations, and step outputs.

### Case E: Infrastructure Failure (Expected: INFRA_ERROR, Exit 3 / Fail-Closed)
- **Scenario**: `--db /nonexistent/path/db.sqlite` or unparseable database.
- **Validation**:
  - `status`: `INFRA_ERROR`
  - Exit code: `3`
  - Action fails closed immediately. It is **never** silently converted to PASS.
