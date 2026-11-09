# VerifyCI Verdicts and Coverage

VerifyCI separates three questions that other gates conflate:

1. **What is the verdict?** (`PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR`, `REVIEW`)
2. **How complete was the analysis?** (`COMPLETE`, `PARTIAL`, `UNKNOWN` per check)
3. **Why?** (closed reason-code catalog: findings, gaps, review reasons, faults)

Uncertainty never passes. A green build alone never promotes a claim.

---

## Verdict ladder

Precedence: **ERROR > FAIL > INCONCLUSIVE > REVIEW > PASS**.

| Verdict | Exit | Meaning | Evidence |
|---|:---:|---|---|
| `PASS` | `0` | Every blocking check is `PASS`/`NOT_APPLICABLE` with `COMPLETE` effective coverage, no open unwaived finding, no fault. | `verdict.status`, per-check results |
| `FAIL` | `1` | At least one blocking finding is `OPEN` after waivers. | `findings[]` with fingerprint, evidence, premises |
| `INCONCLUSIVE` | `2` | A blocking check is incomplete (unaccepted gap) or its effective coverage is not `COMPLETE`. | `check_results[].coverage_gaps[]` |
| `ERROR` | `3` | A fault reason code: internal fault, missing/ambiguous Git object, invalid policy, manifest mismatch, `check_not_validated`, stale cache. | `verdict.fault_reason_codes`, `diagnostics[]` |
| `REVIEW` | `4` | Review condition: policy change, gate-integrity change, stale waiver/acceptance. | `verdict.reason_codes`, `gate_integrity` |

`exit_code` in the bundle always matches the table.

### ERROR is not a verdict about the code

An `ERROR` means the gate could not establish a verdict. Examples:

- `missing_git_object`, `shallow_history`, `ambiguous_merge_base`
- `invalid_policy` (unparseable or schema-invalid target policy)
- `manifest_mismatch` (installed package disagrees with the published manifest)
- `check_not_validated` — the build lacks valid signed release-validation
  evidence. Internal/dev builds therefore can never emit `PASS`.

Resource limits that are gaps rather than faults (`parse_resource_limit`,
`rename_limit_exceeded`) are reported as `INCONCLUSIVE` with the real gap code,
not as `internal_fault`.

---

## Coverage

Each `CheckResult` has a declared `coverage` and an `effective_coverage()`:

| Coverage | Meaning |
|---|---|
| `COMPLETE` | The check enumerated its declared scope and resolved every candidate. |
| `PARTIAL` | Some part of the scope produced an unaccepted gap. |
| `UNKNOWN` | The check could not enumerate its scope (e.g. budget exhausted, unsupported language). |

A check that returns `NOT_APPLICABLE` with `COMPLETE` coverage does not lower the
verdict, but it also never raises it.

---

## Reason-code classes

| Class | Effect | Examples |
|---|---|---|
| Finding | Drives `FAIL` when blocking and `OPEN` | `guard_removed`, `dangerous_call`, `symbol_live`, `secret_detected` |
| Gap | Drives `INCONCLUSIVE` unless accepted | `mapping_unresolved`, `unsupported_language`, `solver_unknown`, `budget_exhausted` |
| Fault | Forces `ERROR` | `internal_fault`, `missing_git_object`, `invalid_policy` |
| Review | Drives `REVIEW` when nothing outranks it | `policy_change_review`, `gate_integrity_review` |
| Diagnostic | Explains a non-verdict condition | `stale_acceptance_present`, `cache_integrity_mismatch` |

### Acceptable gaps vs analytical gaps

Only these gaps are scope exclusions that a reviewed acceptance may remove:

`mapping_unresolved`, `dynamic_target_unresolved`, `dynamic_call`,
`unknown_decorator`, `unresolved_import`, `unknown_call_on_path`,
`frontend_capability_missing`, `unsupported_language`,
`unsupported_syntax_version`, `lfs_content_unavailable`.

Accepting all remaining gaps can lift `INCONCLUSIVE` to `PASS` **only** when the
only reason for incomplete enumeration was an excluded file type
(`unsupported_language`, `frontend_capability_missing`). The lifted result
records every accepted exclusion under
`check_results[].scope_enumeration.accepted_exclusions[]` and
`accepted_gaps[]` in the bundle. Analytical gaps (`solver_unknown`,
`semantic_alignment_unresolved`, `parse_error`, `parse_resource_limit`,
`budget_exhausted`, `watchdog_interrupted`) stay `INCONCLUSIVE` even when
accepted; `taint_path_unresolved` and `secret_candidate_ambiguous` cannot be
accepted at all.

---

## Waivers

A waiver suppresses one finding by fingerprint and check, for a bounded date
range, with a named approver. Waivers are policy records in
`.verifyci/policy.toml`:

```toml
[waivers.known-fp]
check = "security"
defect_id = "SEC-DANGEROUS-CALL"
fingerprint = "vci1:…"
reason = "Reviewed sandbox launcher"
approved_by = "@security"
created = "2026-10-01"
expires = "2026-12-31"
```

An inactive waiver does not suppress the finding; it adds
`waiver_review` and `stale_waiver_present`. Waivers never create `PASS` on
their own when coverage is incomplete.

---

## SARIF mapping

| Verdict | SARIF |
|---|---|
| `PASS` | `executionSuccessful: true`, zero results |
| `FAIL` | `level: "error"` |
| `INCONCLUSIVE` / `ERROR` / `REVIEW` | `level: "warning"` on diagnostics; `executionSuccessful: false` only for `ERROR` |

The verdict is also available at `runs[0].properties.verdict`, and each result
carries `partialFingerprints["verifyciFingerprint/v1"]` for stable deduplication
in code scanning.
