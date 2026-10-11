# VerifyCI

**Deterministic, local-first code verification for agentic pull requests and diffs.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](pyproject.toml)
[![Architecture: Local-First](https://img.shields.io/badge/architecture-local--first-green.svg)](docs/architecture.md)
[![Verification: Deterministic](https://img.shields.io/badge/verification-deterministic-brightgreen.svg)](docs/verdicts.md)
[![Output: SARIF_v2.1.0](https://img.shields.io/badge/output-SARIF_v2.1.0-orange.svg)](docs/architecture.md)

VerifyCI is an open-source verification gate for autonomous AI agents and automated code modifications.
Repository code is indexed into a bitemporal Code Property Graph (CPG), proposed diffs are mathematically mapped onto that graph, and deterministic policy checkers verify structural integrity, blast radius, invariant adherence, and removal provenance.

> **LLMs propose — deterministic checks verify.**  
> VerifyCI replaces prompt-based guesswork with mathematically grounded evidence.

---

## Installation

```bash
pip install verifyci
```

*(VerifyCI requires Python 3.12+ and runs locally on your workstation or CI runner. To install from source for development: `git clone https://github.com/NeutronZero/VerifyCI.git && cd VerifyCI && pip install -e .`)*

---

## 30-Second Example

### 1. Initialize and Ingest a Repository

```bash
# Initialize VerifyCI database (.verifyci/)
verifyci init .

# Ingest codebase to build the bitemporal Code Property Graph
verifyci ingest .

# Inspect graph statistics
verifyci stats
```

### 2. Verify a Diff (Clean Patch → PASS)

When an agent proposes a valid code modification inside an entity span:

```bash
git diff > change.patch
verifyci verify-diff --diff-file change.patch
```

Output:
```text
PASS: all_checks_passed_behavior_not_verified (63c3a9f0-29c8-47f3-b547-b2488417c805)
files: src/service.py
```
Exit code: `0`

*(Every PASS honestly discloses `all_checks_passed_behavior_not_verified`: structural grounding and invariants passed, but runtime semantics remain the domain of functional tests.)*

### 3. Verify a Diff (Guard Removal → FAIL)

When an agent diff removes a security guard or introduces a hardcoded secret:

```bash
verifyci verify-diff --diff-file bad_agent_patch.patch
```

Output:
```text
FAIL: blocking_check_failed (97a1d1e4-84d5-48fa-bb64-c852467d130a)
files: src/auth.py
```
Exit code: `1`

---

## What Problem Does VerifyCI Solve?

Autonomous AI coding agents frequently propose diffs that seem superficially plausible but introduce subtle, dangerous defects:
- **Silently deleting or inverting defensive security guards** (auth checks, bounds checks, validation gates).
- **Fabricating removals** of code that was never present in the base revision.
- **Introducing ungrounded edits** outside recognized function or class spans.
- **Introducing high-entropy hardcoded secrets** or forbidden architectural calls (`eval`, `exec`).
- **Triggering unchecked blast radiuses** across transitive call chains without test coverage.

VerifyCI detects and halts these defects before unit tests, integration pipelines, or human reviewers are engaged.

---

## How VerifyCI Differs

| Capability | LLM Judge / Agent Reviewer | Traditional Linter (flake8, ESLint) | Generic Security Scanner (SAST) | VerifyCI |
|---|---|---|---|---|
| **Determinism** | ❌ Non-deterministic; prompt drift; hallucination risk | ✅ Deterministic | ✅ Rule-based | ✅ 100% Deterministic |
| **Graph-Aware Grounding** | ❌ Context window limited; cannot ground AST spans | ❌ File-local only; no transitive call-graph | ⚠️ Statistical or dataflow heuristic | ✅ Bitemporal Code Property Graph |
| **Stale / Fabricated Deletions** | ❌ Cannot verify what existed in base commit | ❌ Does not evaluate base revisions | ❌ Ignores base-revision lineage | ✅ Verifies removed lines against stored base snippets |
| **Evidence & Provenance** | ❌ Unverifiable natural language opinions | ❌ Error messages only | ❌ Vulnerability reports only | ✅ Cryptographically verifiable Certificate & citations |
| **Fail-Closed Gate** | ❌ Inability is often disguised as approval | ⚠️ Exit code on lint error | ⚠️ High false-positive rate | ✅ Fail-closed: ungrounded diffs decline (`INCONCLUSIVE`) |
| **Infrastructure Isolation** | ❌ SaaS / Cloud dependent | ✅ Local-first | ⚠️ Often requires cloud dashboard | ✅ 100% Local-first; zero cloud required |

---

## The Verdict Model

VerifyCI enforces a strict, honest exit ladder. **Infrastructure failures are never disguised as verification verdicts**, and **inability to verify is never turned into a passing verdict**.

| Verdict | Exit Code | Semantic Meaning | Action Required |
|---|:---:|---|---|
| `PASS` | `0` | Grounded in known entities; all deterministic checks passed; evidence cited | Safe to proceed with merge / pipeline |
| `FAIL` | `1` | A blocking check failed (guard removal, secret, forbidden call, forged deletion) | Patch rejected; fix code or sign waiver |
| `HUMAN_REVIEW` | `2` | Policy file modified in diff, non-blocking check failed, or non-code fast path | Escalate to human code reviewer |
| `INCONCLUSIVE` | `2` | Inability to ground diff (stray edits outside entity spans, binary files, missing base) | Position edits inside spans; ingest base |
| `INFRA_ERROR` | `3` | Graph database missing, locked, or corrupt; revision not found | Run `verifyci ingest .`; fix DB path |
| `TIMEOUT` | `3` | Verification execution exceeded maximum allotted deadline | Increase timeout parameter |

For detailed documentation on each outcome, see [docs/verdicts.md](docs/verdicts.md).

---

## Machine-Readable Exports

VerifyCI supports first-class machine-readable exports directly from the CLI:

### 1. Stable JSON Certificate Export

```bash
verifyci verify-diff --diff-file change.patch --format json --output cert.json
```

Exports a structured, machine-readable JSON document conforming to the VerifyCI Certificate specification:
- Authoritative `Certificate` with premises, traces, and evidence snippets.
- `VerificationReport` with all individual check outcomes.
- Provenance metadata (revision ID, touched files, changed entities).
- Hard boundary: raw secret strings are strictly redacted and never leaked.

### 2. OASIS SARIF v2.1.0 Export (GitHub Code Scanning)

```bash
verifyci verify-diff --diff-file change.patch --format sarif --output results.sarif
```

Exports standard SARIF v2.1.0 compatible with GitHub Code Scanning, SonarQube, and IDEs:
- `FAIL` maps to `level: "error"`, `kind: "fail"`.
- `HUMAN_REVIEW` maps to `level: "warning"`, `kind: "review"`.
- `INCONCLUSIVE` maps to `level: "note"`, `kind: "open"` (preventing false alarms).
- `INFRA_ERROR` marks `executionSuccessful: false`.

---

## GitHub Actions Integration

Add VerifyCI directly to your GitHub pull-request workflows using our composite action:

```yaml
name: VerifyCI Gate

on:
  pull_request:

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

      # Run VerifyCI composite action (release tag or local checkout)
      - uses: NeutronZero/VerifyCI@v0.1.0
        id: verifyci
        with:
          format: sarif
          output-file: verifyci-results.sarif

      # Upload SARIF findings to GitHub Security tab
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: verifyci-results.sarif
```

See [action.yml](action.yml) for full parameter configuration.

---

## Agent Integration (Model Context Protocol)

VerifyCI exposes a native Model Context Protocol (MCP) server so coding agents (like Claude Desktop, Cursor, or custom LLMs) can inspect the code graph and self-verify their diffs before submitting:

```bash
# Run FastMCP server over stdio
verifyci serve --db .verifyci/verifyci.db

# Or run over HTTP
verifyci serve --transport http --port 8000
```

Available tools exposed to agents:
- `graph.query`: Query the code graph with time-travel (`asOf`) support.
- `verify.diff`: Test a proposed diff against repository invariants and receive structured feedback.

---

## Core Invariants & Grounding Rules

VerifyCI operates under rigorous mathematical invariants:

1. **Every changed line must land inside a code entity span**: Edits outside entity spans (stray comments, flags, module constants) force `INCONCLUSIVE`.
2. **Deletions must match stored base snippets**: Any deletion of code that contradicts the stored base revision is `FAIL` (prevents forged or stale diffs).
3. **No text-half laundering**: A commit mixing groundable code with unreadable binary or mode-only changes forces `INCONCLUSIVE`.
4. **Base policy file protection**: Modifications to `.verifyci/invariants.yaml` or `.verifyci/waivers.yaml` cannot pass automatically and force `HUMAN_REVIEW`.
5. **Fail-closed security preemption**: When a diff text introduces an intrinsic secret or forbidden call, it fails closed as `FAIL` (exit 1) even if the database is missing or unreadable.

---

## Empirical Benchmarks & Evidence Reproduction

VerifyCI is characterized against frozen, SHA-256-pinned empirical corpora:

- **B1: Invariants Evaluation** (`tests/evaluation/labels/invariants_v2.jsonl`, SHA-256 `e17d65878ccc5330`): 26 cases covering secrets and forbidden calls.
- **B2: BEIR Retrieval** (`benchmarks/beir/`): 62 graded queries across 60 docs evaluating hybrid BM25 + dense retrieval.
- **C1: Patch Evaluation** (`benchmarks/patch_corpus/cases.jsonl`, SHA-256 `5ff5ab1b4d075559`): 17 cases measuring synthetic agent wrong-patch detection.
- **C2: Blast Radius** (`benchmarks/blast_corpus/cases.jsonl`, SHA-256 `efbf6b4e12e62fd1`): Multi-hop topology traversal.
- **CAP006: Temporal Lineage** (`benchmarks/temporal_corpus/cap006/`): 64/64 agreement, 8/8 fail-closed tripwires caught.
- **CAP007: Production Scale** (`benchmarks/retrieval_corpus/cap007/`): 174,779 nodes / 165,570 edges graph retrieval.
- **CAP008: Concurrency & Storage** (`benchmarks/concurrency_corpus/cap008/`): 64/64 agreement under multi-process worker contention with zero lost updates.

To reproduce benchmarks locally:
```bash
pytest tests/evaluation/ tests/performance/ -q
```
For complete details and hash verification, see [docs/benchmarks.md](docs/benchmarks.md) and [V1_EVIDENCE.md](V1_EVIDENCE.md).

---

## Known Limitations

- **Language Scope**: Deep semantic CPG entity extraction currently supports Python, TypeScript, JavaScript, C, and C++. Non-code files (markdown, plaintext) route to human review or bypass without semantic claims.
- **Base Graph Dependency**: Diff verification requires an initialized graph database ingested from the base revision to evaluate removal provenance and entity anchors.
- **Deterministic Scope**: VerifyCI verifies invariant adherence, entity grounding, and structural blast radius; runtime semantics and functional logic remain the domain of execution tests.

---

## Documentation Index

- [Quickstart Guide (5-Minute Walkthrough)](docs/quickstart.md)
- [CI/CD Pipeline Integrations (GitHub Actions, GitLab CI, Bitbucket)](docs/integrations/ci_pipelines.md)
- [Adoption Walkthrough (End-to-End Example)](docs/examples/basic_walkthrough.md)
- [Verdict System & Exit Code Reference](docs/verdicts.md)
- [System Architecture & Pipeline Details](docs/architecture.md)
- [Extending VerifyCI (Writing Custom Checkers)](docs/extension.md)
- [Benchmarks & Evidence Reproduction](docs/benchmarks.md)
- [API & Contract Stability Policy](STABILITY.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

## License

VerifyCI is licensed under the [MIT License](LICENSE).
