# Adding a verification check

Checks are deterministic modules registered in the frozen manifest. Adding one
is a contract change: it needs a check spec, evidence kinds, a corpus, and a
promotion record before it can block.

---

## 1. Contract

A check is a function `run(context: CheckContext) -> CheckResult` in
`verifyci/checks/<name>.py`. `CheckResult` (in `verifyci/contracts/model.py`)
carries:

| Field | Meaning |
|---|---|
| `check_id`, `check_version` | Identity and version of the check. |
| `tier`, `maturity` | `blocking`/`advisory`, `shadow`/promoted maturity. |
| `outcome` | `PASS`, `FAIL`, `NOT_APPLICABLE`, `INCONCLUSIVE`, `ERROR`. |
| `coverage` | `COMPLETE`, `PARTIAL`, `UNKNOWN`. |
| `evaluated_scope`, `scope_enumeration`, `candidate_discovery`, `applicability_evidence` | What was examined and how completely. |
| `coverage_gaps` | `CoverageGap(reason_code, subject)` from the closed catalog. |
| `findings` | Blocking findings built with `make_finding(...)`. |

Use the helpers in `verifyci/checks/base.py`:

- `make_result(...)` for normal results;
- `make_finding(...)` for defects (validates defect id/evidence-kind pairing,
  computes the stable fingerprint, and binds premises to commits/blobs/policy);
- `gap(code, subject)` for gaps;
- `budget_exhausted_result(...)` when a deadline or budget is hit;
- `inconclusive_gap_result(...)` for environmental limits that are not faults.

`ERROR` is reserved for faults. Never return `ERROR` for an unmodelled construct;
return `INCONCLUSIVE` with a gap.

---

## 2. Register the check

1. Add a `CheckSpec` in `verifyci/contracts/manifest.py`:

```python
_MY_CHECK = CheckSpec(
    check_id="mycheck",
    check_version=1,
    tier=Tier.BLOCKING,
    maturity=Maturity.SHADOW,          # blocking requires a promotion record
    method="mycheck",
    method_version=1,
    supported_languages=("python",),
    supported_syntax=("python_3_12",),
    defect_ids=("MY-DEFECT-ID",),
    reason_codes=("my_reason",),
    evidence_kinds=("reference",),
    corpus_id="mycorpus-v1",
    corpus_hash="sha256:…",
    promotion_record_hash="",
)
```

2. Register the defect id → reason code in
   `verifyci/contracts/reason_codes.py` (`DEFECT_REASON_CODES`) and the allowed
   evidence kinds in `EVIDENCE_KINDS_BY_DEFECT`; add the reason code to the
   findings/gaps catalog.
3. Add `CHECK_SPECS`/`CHECK_ORDER` entries and map the runner in
   `verifyci/gate/orchestrator.py::_CHECK_RUNNERS`.
4. Add the check id to any policy validation lists (`_CHECK_IDS` in
   `verifyci/gate/policy.py`).

`validate_manifest()` enforces the invariants: every check in `CHECK_ORDER` has
a spec, a blocking check cannot be shadow, and a non-shadow check needs a
promotion record hash.

---

## 3. Evidence requirements

- Findings must cite source-level evidence (`EvidenceKind`) and include premises
  that already bind base/merge-base/head, the authoritative policy hash,
  check version, and toolchain.
- A finding without a validated witness is not a FAIL: use a gap.
- `subject` should carry `path`, `symbol`, and `line` (or `head_span`) so SARIF
  can point at the right location and fingerprints stay stable.

---

## 4. Tests and corpora

A new check needs:

1. A frozen corpus with expected outcomes, coverage, gaps, and findings
   (`corpora/<check>/cases.jsonl` + fixtures + `SHA256SUMS`). Oracles are frozen
   before measurement and never rewritten to match an implementation.
2. An empirical benchmark test (precision/recall thresholds are part of the
   check spec).
3. Adversarial tests for bypasses and fail-closed behaviour.
4. `docs/` describing the new defect id and reason codes.

Run the gate test suite and the new corpus before opening a PR:

```bash
python -m pytest tests/v3 -q -n 0
python -m ruff check . --select E,F,B023
```

---

## 5. Promotion

A shadow check becomes blocking only with an independent promotion record under
`evidence/release/` (see [release-evidence.md](release-evidence.md)). Promotion
is a separate commit; it is never inferred from a green CI run.
