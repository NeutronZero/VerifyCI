# VerifyCI Verdict System

VerifyCI adheres to a strict, honest verdict model. In VerifyCI, **infrastructure errors are never conflated with verification verdicts**, and **inability to verify is never disguised as a passing verdict**.

---

## Verdict Summary Table

| Verdict | Category | Exit Code | Meaning | SARIF Mapping | Action |
|---|---|:---:|---|---|---|
| `PASS` | Success | `0` | Grounded in known entities; all deterministic checks passed; evidence and traces non-empty | `invocations.executionSuccessful: true` (0 alerts) | Proceed with merge |
| `FAIL` | Failure / Rejection | `1` | A deterministic blocking check failed (guard removal, forbidden call/import, secret, forged deletion) | `level: "error"`, `kind: "fail"` | Fix patch or add signed waiver |
| `HUMAN_REVIEW` | Uncertainty / Escalation | `2` | Non-blocking failures, policy file modified in diff, or non-code fast path | `level: "warning"`, `kind: "review"` | Route to human reviewer |
| `INCONCLUSIVE` | Inability | `2` | Unable to ground diff or establish checks (stray lines, binary content, missing entities) | `level: "note"`, `kind: "open"` | Position edits in spans; ingest base |
| `INFRA_ERROR` | Infrastructure | `3` | Graph store missing, locked, corrupt, or revision not found | `executionSuccessful: false`, `ruleId: "storage_unavailable"` | Run `verifyci ingest .`; fix DB path |
| `TIMEOUT` | Operational | `3` | Verification execution exceeded maximum allotted time limit | `executionSuccessful: false`, `ruleId: "verification_timeout"` | Extend timeout; optimize query |

---

## Detailed Verdict Specifications

### 1. `PASS` (Exit Code 0)

- **Semantic Meaning**: The patch successfully grounds into known code entities in the bitemporal Code Property Graph, all deterministic checkers passed, and non-empty execution traces and evidence citations exist.
- **Honest Qualifier**: Every PASS outputs the rationale `all_checks_passed_behavior_not_verified`. This explicitly discloses that structural grounding, invariant satisfaction, and blast-radius constraints were mathematically verified, but runtime semantic correctness remains the domain of functional tests.
- **When it occurs**:
  - All modified lines land inside valid entity spans (functions, methods, classes).
  - All invariant checks (`secrets_scan`, `forbid_call`, `forbid_import`, `check_call`) pass.
  - Deletions match base-revision code snippets.
  - Non-empty CPG evidence is cited.
- **CLI Representation**:
  ```text
  PASS: all_checks_passed_behavior_not_verified (63c3a9f0-29c8-47f3-b547-b2488417c805)
  files: src/core.py
  ```
- **Next Steps**: Proceed with automated testing and pull-request merge.

---

### 2. `FAIL` (Exit Code 1)

- **Semantic Meaning**: A blocking deterministic check flagged an active violation in the diff.
- **When it occurs**:
  - **Hardcoded Secret**: Added lines match high-entropy patterns, API keys, private keys, or credentials (`secrets_scan`).
  - **Guard Removal / Inversion**: The patch deletes or inverts an authorization check, bound check, or validation guard (`guard_condition_inversion`).
  - **Fabricated Deletion**: The patch deletes lines that did not exist in the stored base revision (`removal_provenance`).
  - **Forbidden Calls / Imports**: The patch adds calls or imports forbidden by `.verifyci/invariants.yaml` (e.g. `eval`, `exec`).
  - **Invalid Configuration**: Added configuration files (e.g., `pyproject.toml`, YAML, JSON) fail syntax parsing.
  - **Security Preemption**: When a diff text contains an intrinsic violation (like an added secret or forbidden call), it fails closed as `FAIL` (exit 1) even if the database is missing or unreadable (`security_violation_preempts_infra_error`).
- **CLI Representation**:
  ```text
  FAIL: blocking_check_failed (97a1d1e4-84d5-48fa-bb64-c852467d130a)
  files: src/api.py
  ```
- **Next Steps**: Inspect the failed check explanation. Either correct the patch or, if the change is verified and intentional, provide a cryptographically verified `SignedIntentWaiver` in `.verifyci/waivers.yaml`.

---

### 3. `HUMAN_REVIEW` (Exit Code 2)

- **Semantic Meaning**: The verification engine cannot deterministically approve the change without human oversight.
- **When it occurs**:
  - **Policy File Integrity**: The diff modifies `.verifyci/invariants.yaml` or `.verifyci/waivers.yaml` (`unverified_policy_change`). An agent or contributor cannot unilaterally modify the rules governing verification.
  - **Non-Code Fast Paths**: Diffs modifying only documentation, configuration, or test suites. Because there are no code entities to trace, evidence is empty by construction, which routes to HUMAN_REVIEW rather than an ungrounded PASS.
  - **Non-Blocking Invariant Violations**: Invariants configured with `blocking: false` that did not pass.
- **CLI Representation**:
  ```text
  HUMAN_REVIEW: unverified_policy_change: gate configuration modified in diff (a1b2c3d4-...)
  files: .verifyci/invariants.yaml
  ```
- **Next Steps**: Escalate the pull request to a human reviewer or security maintainer.

---

### 4. `INCONCLUSIVE` (Exit Code 2)

- **Semantic Meaning**: Inability to verify. The verification engine ran, but could not establish grounding or evidence for the diff.
- **When it occurs**:
  - **Ungrounded Entities**: The diff touches files that do not exist in the base revision graph.
  - **Stray Edits**: Edits land outside any recognized code entity span (e.g. module-level comments, stray statements, ungrounded flags).
  - **Opaque / Binary Content**: The diff includes binary files or file-mode changes where text content is not carried.
  - **Suffix-Only Ambiguity**: Diff file paths match multiple stored paths with conflicting entity identities.
  - **Zero-Edge Checks**: A blocking check evaluated 0 relevant edges in the graph (`unestablished_blocking_checks`).
- **CLI Representation**:
  ```text
  INCONCLUSIVE: checks_ran_but_nothing_established (88fa90bc-...)
  files: ghost.py
  ```
- **Next Steps**:
  1. Ensure the base commit of the PR is ingested into the VerifyCI graph (`verifyci ingest .`).
  2. Ensure code edits land within defined function, method, or class blocks.

---

### 5. `INFRA_ERROR` (Exit Code 3)

- **Semantic Meaning**: Infrastructure failure. VerifyCI was unable to read or access the required graph or database substrate.
- **When it occurs**:
  - Database file does not exist (`db_not_found`).
  - SQLite database is locked by another process (`db_locked`).
  - Database file is corrupted or unreadable (`db_unreadable`).
  - Specified revision ID does not exist in the database (`revision_not_found`).
- **Honest Isolation**: Infrastructure errors are **never converted into verification verdicts**. A missing database will never yield a `PASS` or `INCONCLUSIVE`.
- **CLI Representation**:
  ```text
  INFRA_ERROR: storage_unavailable:db_not_found (00000000-...)
  ```
- **Next Steps**:
  1. Verify the `--db` path passed to VerifyCI.
  2. Initialize and ingest the repository using `verifyci init . && verifyci ingest .`.
  3. Ensure file permissions allow read and write access to the `.verifyci` directory.

---

### 6. `TIMEOUT` (Exit Code 3)

- **Semantic Meaning**: An orchestration task or complex graph query exceeded its execution deadline.
- **When it occurs**:
  - A task run via `verifyci run` or scheduled DAG evaluation exceeds the `--timeout` parameter.
- **CLI Representation**:
  ```json
  {
    "status": "TIMEOUT",
    "at_most_once": true,
    "ledger_head": "..."
  }
  ```
- **Next Steps**: Increase the timeout argument or optimize the graph query scope.
