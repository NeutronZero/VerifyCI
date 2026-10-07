# VerifyCI V0.1.0 Public Release Verification Record

This document records post-publication validation evidence for VerifyCI V0.1.0 across PyPI, GitHub Releases, and live GitHub Cloud Actions.

---

## 1. Release Provenance & Checksums

| Attribute | Verified Value |
|---|---|
| **Release Version** | `0.1.0` |
| **Release Tag** | `v0.1.0` (`505bb96d08e7ad25ad631bd0709974344ad5349f`) |
| **Target Commit** | `a6fdb9cdc21b375bf1624b21356fdd21e7ed48a3` |
| **PyPI Project** | [https://pypi.org/project/verifyci/0.1.0/](https://pypi.org/project/verifyci/0.1.0/) |
| **GitHub Release** | [https://github.com/NeutronZero/VerifyCI/releases/tag/v0.1.0](https://github.com/NeutronZero/VerifyCI/releases/tag/v0.1.0) |
| **Trusted Publishing** | Enabled (GitHub Actions OIDC -> PyPI environment `pypi`) |
| **Workflow Run** | Run `37636586424` on `NeutronZero/VerifyCI` |

### Published Distribution Checksums (`SHA256SUMS.txt`)

```text
d1e1f684f8a8980fa0445539020589d45f0e78a1cc9c5dc22e6c379c0459b3b2  verifyci-0.1.0.tar.gz
98663d635a2e2ec040db3ca3be16716d838314f1151103339f65a6dba3394dc8  verifyci-0.1.0-py3-none-any.whl
```

---

## 2. Public PyPI Installation Validation

- **Environment**: Clean, isolated temporary virtualenv outside repository root.
- **Install Command**: `pip install --no-cache-dir verifyci==0.1.0`
- **Module Resolution**:
  ```text
  C:\Users\...\venv\Lib\site-packages\verifyci\__init__.py
  ```
- **CLI Startup**: `verifyci --help` exited 0.
- **Repository Commands**: `verifyci init .`, `verifyci ingest .`, `verifyci stats` executed cleanly.

---

## 3. Public Verification Matrix (Measured Against Installed PyPI Package)

| Test Case | Scenario | Expected | Actual Result | Measured Exit Code |
|---|---|:---:|---|:---:|
| **Case A** | Harmless change inside entity span | PASS (0) | `PASS: all_checks_passed_behavior_not_verified` | `0` |
| **Case B** | Security guard removal | FAIL (1) | `FAIL: blocking_check_failed` | `1` |
| **Case C** | Inconclusive / ungrounded edit | INCONCLUSIVE (2) | `INCONCLUSIVE: checks_ran_but_nothing_established` | `2` |
| **Case D** | Hardcoded API token | FAIL (1) | `FAIL: blocking_check_failed` (Token redacted) | `1` |
| **Case E** | Substrate DB missing / corrupt | INFRA_ERROR (3) | `INFRA_ERROR: storage_unavailable:db_not_found` | `3` |

---

## 4. Machine-Readable Export Validation

- **JSON Certificate Export**:
  - Schema: `https://verifyci.org/schemas/v1/certificate-report.json`
  - Version: `1.0`
  - Verdict: `FAIL` (exit code 1)
  - Certificate: Contains `certificate_id`, `premises`, `evidence`, `conclusion`.
  - Secret Leakage: Zero raw secret characters leaked; detection logged with token redacted.
- **OASIS SARIF v2.1.0 Export**:
  - Version: `2.1.0`
  - Tool Name: `VerifyCI`
  - Rule IDs: `secrets_scan` (`level: "error"`), `semi_formal` (`level: "note"`), `provenance_check` (`level: "warning"`).
  - Infrastructure Failure: Reported via `storage_unavailable` alert with `executionSuccessful: false`, exiting 3 without masking infrastructure failure.

---

## 5. Live GitHub Cloud Action Validation

- **Test Repository**: [`NeutronZero/verifyci-action-demo`](https://github.com/NeutronZero/verifyci-action-demo)
- **Workflow Run**: [`37640746311`](https://github.com/NeutronZero/verifyci-action-demo/actions/runs/37640746311)
- **Action Reference**: `uses: NeutronZero/VerifyCI@v0.1.0`

### Cloud Execution Results

| Job Name | Stage Tested | Action Verdict Output | Exit Code | Step Outcome | Status |
|---|---|---|:---:|:---:|:---:|
| `case-a-clean` | Harmless edit | `VerifyCI PASSED` | 0 | `success` | **PASSED** (23s) |
| `case-b-blocking` | Guard removal | `VerifyCI FAILED` | 1 | `failure` | **PASSED** (28s, fail-closed) |
| `case-c-policy-tampering` | Policy modified | `VerifyCI HUMAN_REVIEW` | 2 | `failure` | **PASSED** (26s, fail-closed) |
| `case-d-secret` | Synthetic token | `VerifyCI FAILED` | 1 | `failure` | **PASSED** (21s, zero leak) |
| `case-e-infra-error` | Corrupted DB path | `VerifyCI INFRA_ERROR` | 3 | `failure` | **PASSED** (24s, honest exit 3) |

---

## 6. Findings & Observations

1. **Base Ingestion Sequencing**:
   When using VerifyCI in CI without a pre-existing `.verifyci/` cache, `verifyci ingest` must be performed against the base commit (`HEAD~1` or `$GITHUB_BASE_REF`) before edits are staged. If ingested after the edits are applied, `removal_provenance` will fail closed because the removed lines will not exist in the ingested graph.
2. **Release History Integrity**:
   No runtime bugs, broken entrypoints, or omitted distribution artifacts exist in the published V0.1.0 packages. All contracts and historical evidence remain preserved.
