# VerifyCI

**Deterministic, local-first pre-merge verification gate for AI-authored pull requests and diffs.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](pyproject.toml)
[![Architecture: Local-First](https://img.shields.io/badge/architecture-local--first-green.svg)](docs/architecture.md)
[![Output: SARIF_v2.1.0](https://img.shields.io/badge/output-SARIF_v2.1.0-orange.svg)](docs/architecture.md)

VerifyCI is a local-first, deterministic pre-merge verification gate designed to halt semantic regressions, ungrounded edits, security violations, and contract breakage in AI-generated code modifications before tests or human review.

The verification core runs **100% offline** on Git object databases with **zero external API keys, zero LLM calls, zero databases, and zero servers**.

---

## The PASS Contract

Per VerifyCI v3.1 specification (§1.3):

> **PASS means every applicable blocking check in this release completed with COMPLETE coverage over its declared scope and no unwaived declared defect was established. PASS covers only the defect families listed as blocking in the release manifest [grounding, deletion, contract, security]; families that are shadow or not shipped [semantic] were not enforced. Scope excluded by reviewed coverage acceptances is listed in the evidence bundle. PASS is not a claim that the code is correct or that the diff is safe in general. The evidence bundle states what was checked, the applicable assumptions, the excluded scope, accepted gaps, and any waived findings.**

---

## Installation

```bash
pip install verifyci
```

*(VerifyCI requires Python 3.12+ and runs locally on your workstation or CI runner.)*

---

## Quickstart CLI

Run the gate against any pull request or commit range:

```bash
# Verify a PR branch against origin/main
vc gate --repo . --base origin/main --head HEAD --format sarif --output verifyci-results.sarif
```

### Exit Codes & Verdicts

VerifyCI enforces a strict exit ladder:

| Verdict | Exit Code | Meaning |
|---|:---:|---|
| `PASS` | `0` | Every blocking check completed with `COMPLETE` coverage; no unwaived declared defect found. |
| `FAIL` | `1` | Blocking defect established with validated witness or exact provenance. |
| `INCONCLUSIVE` | `2` | Coverage incomplete, unmodelled syntax encountered, or analysis budget exhausted. |
| `ERROR` | `3` | Internal failure, corrupt/missing Git object, or invalid policy schema. |
| `REVIEW` | `4` | Policy or gate-integrity files modified; requires designated codeowner review. |

---

## GitHub Actions Integration

Add VerifyCI directly to your GitHub pull-request workflows using our composite action:

```yaml
name: VerifyCI Gate

on:
  pull_request:
    branches: [ main ]

jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install VerifyCI
        run: pip install verifyci

      - name: Run VerifyCI Gate
        uses: NeutronZero/VerifyCI@main
        with:
          base-ref: "origin/${{ github.base_ref }}"
          head-ref: "HEAD"
          format: "sarif"
          output-file: "verifyci-results.sarif"

      - name: Upload SARIF Results
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: "verifyci-results.sarif"
```

---

## Declared Defect Families

1. **Semantic Regressions (`semantic` - shadow tier in v3.1.0)**:
   - Protected guard removal, weakening, or inversion (`SEM-GUARD-REMOVED`, `SEM-GUARD-WEAKENED`, `SEM-GUARD-INVERTED`)
   - Swapped argument or return bindings (`SEM-BINDING-SWAP`)
   - Removed protected error paths (`SEM-EXCEPTION-REMOVED`)
2. **Provenance & Grounding (`grounding` - blocking tier)**:
   - Prohibited edits under `deny_changes` rules (`GRD-UNGROUNDED-EDIT`)
3. **Security Regressions (`security` - blocking tier)**:
   - Offline-validated secrets introduced (`SEC-SECRET`)
   - Taint flows to dangerous sinks (`SEC-SECRET-TO-SINK`, `SEC-TAINT-TO-SINK`)
   - Exact policy-forbidden calls (`SEC-DANGEROUS-CALL`)
4. **Caller & Contract Breakage (`contract` - blocking tier)**:
   - Incompatible signatures, parameter removals, or async/sync shifts (`CTR-SIGNATURE-BREAK`)
   - Broken exports or call-site incompatibilities (`CTR-EXPORT-BREAK`, `CTR-CALL-INCOMPATIBLE`)
5. **Unsafe Deletion (`deletion` - blocking tier)**:
   - Removed symbols remaining reachable from entrypoints, exports, or live callers (`DEL-REACHABLE-SYMBOL`)
   - Dangling references (`DEL-DANGLING-REFERENCE`)
   - Dynamic references resolving to removed symbols (`DEL-DYNAMIC-REFERENCE`)

---

## License

MIT License. See [LICENSE](LICENSE) for details.
