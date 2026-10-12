# Shared Frozen-Corpus Conventions (CAP-009 – CAP-013)

This document establishes the binding structural, cryptographic, and evaluation conventions for benchmark corpora CAP-009 through CAP-013, standardizing the patterns established in CAP-002B, CAP-004, CAP-006, CAP-007, and CAP-008.

---

## 1. Directory & File Layout

Each CAP benchmark lives in its own dedicated frozen directory (e.g. `benchmarks/<domain>/<cap_id>/`) and must contain the following standardized artifacts:

| File | Purpose | Requirement |
|---|---|---|
| `cases.jsonl` | Frozen evaluation input cases / diffs / queries | Cryptographically pinned; sealed before measurement |
| `labels.jsonl` | Frozen gold labels / ground-truth judgments | Independently authored; sealed before measurement |
| `config.json` | Manifest & metadata | Contains `experiment_id`, `case_count`, `slice_counts`, `corpus_sha256`, `label_sha256`, `status`, `freeze_rule`, thresholds |
| `CORPUS_SHA256` | Plaintext SHA-256 digest of `cases.jsonl` | Exact hex string + newline |
| `LABEL_SHA256` | Plaintext SHA-256 digest of `labels.jsonl` | Exact hex string + newline |
| `author_cap*.py` | Corpus authoring script | Clean-room synthesis and label generator; no production imports |
| `measure_cap*.py` | Standalone measurement harness | Validates freeze hashes *first*; runs clean-room evaluation; emits `results.json` and `RESULTS.md` |
| `MODE_PROTOCOL.md` | Protocol specification | Formalizes experiment ID, invariants, category distributions, and falsifiers |
| `results.json` | Canonical measurement evidence | Contains per-case rows and provenance binding |
| `RESULTS.md` | Human-readable adjudication report | Predeclared gates, per-slice metrics, evidence classifications |

Reproduction tests are placed in `tests/verification/test_*_cap0XX.py`.

---

## 2. Freeze-Hash Validation Order (Fail-Closed)

Before running any inference, pipeline step, or measurement calculation, `measure_cap*.py` and verification tests must validate:
1. `cases.jsonl` SHA-256 matches `CORPUS_SHA256` and `config.json["corpus_sha256"]`.
2. `labels.jsonl` SHA-256 matches `LABEL_SHA256` and `config.json["label_sha256"]`.
3. If any hash mismatches or file is missing, the harness aborts immediately with a fail-closed error. No measurement proceeds on unverified or drifted corpora.

---

## 3. Ground-Truth Independence & Clean-Room Oracles (P0-1)

1. **Production Code Isolation**: No production code (`verifyci.verification.diffmap`, production detectors, production traversals, or reasoners) may participate in generating labels or ground truth.
2. **Oracle Provenance**: Ground truth must be derived from independently authored source-span annotations, explicit synthetic specifications, or clean-room reference functions.
3. **Static Audit**: Reproduction tests statically assert that `author_cap*.py` does not import production analysis or verification modules.

---

## 4. Provenance Binding in `results.json` (P0-6)

Every emitted `results.json` must record a top-level `provenance` block binding the canonical execution context:

```json
{
  "experiment_id": "CAP-00X",
  "provenance": {
    "git_commit": "cf5d3e8...",
    "git_dirty": false,
    "harness_sha256": "...",
    "oracle_sha256": "...",
    "config_sha256": "...",
    "python_version": "3.12.x",
    "platform": "Windows-..."
  },
  "metrics": { ... },
  "cases": [ ... ]
}
```

---

## 5. Canonical Data Recomputation & Adjudication (P0-6)

1. **Derived Verdicts**: Verification tests and evidence adjudicators (`scripts/adjudicate_cap.py`) must recompute all summary statistics and gate metrics directly from canonical per-case/per-query rows in `results.json`.
2. **Untrusted Flags**: Recorded `"PASS"`, `"MET"`, or `"established": true` fields are never accepted on trust; they are cross-checked against recomputed values.
3. **Integrity Checks**: The number of per-case rows must match `config.json["case_count"]`, case IDs must be unique, and case inputs must correspond to frozen corpus cases.

---

## 6. Evidence Classification Taxonomy

In `RESULTS.md`, every measured gate must be adjudicated under one of four explicit evidence classifications:
1. **Established**: The target threshold was satisfied on a statistically representative, frozen corpus with clean-room oracles.
2. **Measured-Met, Not Established**: The measured metric meets the target, but the workload is synthetic, small, or under non-pinned hardware envelopes.
3. **Measured-Unmet**: The measured metric fell below the predeclared gate threshold. This is published transparently without gate retuning.
4. **Unmeasured**: No ground-truth label set exists (reported as `null`, never `0.0`).

---

## 7. Redaction Boundary & Secret Safety (P0-3)

1. **Corpus vs Runtime**: Synthetic credentials in frozen corpora (`cases.jsonl`) are required to evaluate detection engines.
2. **Leakage Assertion**: Every measure harness must verify that runtime artifacts (logs, serialized reports, evidence bundles, `results.json`, `RESULTS.md`) contain zero raw synthetic secret values via `assert_no_secret_leak()`.
3. **Exclusion**: Frozen input files (`cases.jsonl`) are explicitly excluded from runtime artifact scans, but all generated/output paths are checked.

---

## 8. Reproducible Hardware Envelopes & Mutation Accounting (P1-4, P1-5)

1. **Performance Tiers**: Hardware-sensitive latency/memory gates are enforced strictly on pinned benchmark environments; non-pinned runners verify functionality and capture metrics without gating on volatile clock times. Distributions across OS platforms are never merged.
2. **Mutation Accounting**: All source mutations run in isolated sandboxes or temporary directories; every mutation is classified as `killed`, `survived`, or `equivalent`. Critical mutations must achieve 100% kill rate on the predeclared non-equivalent set.
