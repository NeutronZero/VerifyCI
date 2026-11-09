# VerifyCI API & Contract Stability

This document defines the stability tiers, contract guarantees, and frozen-artifact
policy for VerifyCI **v3.1.10**.

---

## Stability tiers

| Tier | Guarantee | Breaking-change policy |
|---|---|---|
| **Stable / public** | Backwards compatible within a major release | Deprecation notice in a minor release; removal only in a major release (SemVer 2.0.0) |
| **Experimental** | Subject to measurement and refinement; opt-in | May change in any minor release; recorded in CHANGELOG.md |
| **Internal** | No external compatibility guarantee | May change at any time |

---

## 1. Stable / public surface

### CLI

- Entry point: `vc` (`python -m verifyci.cli`).
- Supported command: **`vc gate`**. The v1/v2 commands (`init`, `ingest`,
  `verify-diff`, `stats`, `query`, `deps`, `run`, `verify-chain`, `serve`) are
  retired; invoking them fails argument parsing.

```text
vc gate --repo PATH --base REV [--head REV] [--merge-base REV]
        [--format text|json|sarif] [--output PATH] [--as-of YYYY-MM-DD]
        [--cache-mode none|local|authenticated] [--cache-dir PATH]
        [--allow-local-cache] [--cache-read-only] [--jobs N]
        [--review-mode fail|codeowners]
```

- Exit codes: `0` PASS · `1` FAIL · `2` INCONCLUSIVE · `3` ERROR · `4` REVIEW.
- `--format json` emits the evidence envelope `{"payload": …, "envelope": …}`;
  the verdict is `payload.verdict`.
- `--format sarif` emits SARIF 2.1.0; the verdict is also mirrored at
  `runs[0].properties.verdict`.
- Policy authority: `.verifyci/policy.toml` on the **target base** revision.

### Frozen contracts (`verifyci/contracts/`)

- `model.CheckResult`, `model.Finding`, `model.CoverageGap`, `model.VerdictResult`,
  `model.EvidenceBundle`, `model.Policy`
- `manifest` (check registry, tool version, manifest hash)
- `reason_codes` (closed catalog; reason classes `FAULT`/`REVIEW`/`GAP`/`FINDING`/`DIAGNOSTIC`)
- `release_validation` (independent §15.10 evidence verification)
- Evidence envelope and payload schemas (`verifyci.evidence/v3.1`,
  `verifyci.envelope/v3.1`)

### GitHub Action (`action.yml`)

- Inputs: `path`, `base-ref`, `head-ref`, `format`, `output-file`, `as-of`,
  `review-mode`, `cache-mode`, `cache-dir`, `cache-key`, `cache-key-id`.
- Outputs: `status`, `exit-code`, `report-file`.
- A non-zero gate exit is recorded in `status`/`exit-code` before the step
  fails; `FAIL`/`INCONCLUSIVE` are never lost to shell error handling.

### Trusted-worker IPC (`verifyci_release_trust/ipc.py`)

- Outcomes: `PASS`, `FAIL`, `INCONCLUSIVE`, `ERROR`, `NOT_APPLICABLE`.
- Coverage: canonical `COMPLETE`/`PARTIAL`/`UNKNOWN`; legacy `FULL`/`NONE`
  spellings remain accepted.
- Exit-code mapping: `0` PASS, `1` FAIL, `2` INCONCLUSIVE, `3` ERROR,
  `4` NOT_APPLICABLE (worker boundary).

---

## 2. Experimental surface

- Alternative frontends beyond Python/TypeScript/JavaScript coverage: files are
  reported as `unsupported_language` gaps and may be accepted, but no semantic
  analysis is claimed.
- Cross-file TypeScript reference resolution (import-based) is implemented for
  relative and repository-path specifiers; package-manager aliases are not
  resolved and remain `unresolved_import` gaps.
- Node-based TypeScript witness replay requires a local `node` binary; when it
  is absent the result is `semantic_alignment_unresolved`, never PASS.

---

## 3. Internal implementation

- `verifyci/scope/entities.py` parse-tree extraction details and cache keying.
- `verifyci/runtime/sandbox.py` (test-side container helper; not part of the gate path).
- `verifyci/analysis/`, `verifyci/frontend/`, `verifyci/index/facts.py`,
  `verifyci/index/symbol_index.py` (unused placeholders; no gate dependency).
- `verifyci/evidence/canonical.py` JSON canonicalisation internals.

---

## Frozen evidence & benchmarks

1. **Baseline artifacts are immutable.** The `v1.0-evidence-baseline` tag and
   everything under `corpora/` and `benchmarks/` are frozen and SHA-256 pinned.
   Frozen labels, snapshots, workloads, and oracles are never rewritten to make
   an implementation pass.
2. **New evidence needs new identifiers.** Any new benchmark, ablation, or
   measurement gets a new directory/identifier; remediation and benchmark work
   lands in separate commits.
3. **No retroactive retuning.** Acceptance thresholds and gate definitions are
   declared before a measurement run.
4. **Retired harnesses stay retired.** `benchmarks/latency/` targets the removed
   v1 ingestion API and cannot run against v3.1; it is retained only as frozen
   historical evidence. New latency measurements belong in
   `benchmarks/performance/`.
