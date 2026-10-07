# VerifyCI API & Contract Stability

This document outlines the API stability tiers, contract guarantees, and deprecation policies for VerifyCI.

---

## Stability Tiers

VerifyCI components are classified into three stability tiers: **Stable / Public**, **Experimental**, and **Internal**.

| Tier | Guarantee | Breaking Change Policy |
|---|---|---|
| **Stable / Public** | Backwards-compatible within a major release | Requires deprecation notice across at least one minor release; breaking changes only in major releases (SemVer 2.0.0). |
| **Experimental** | Subject to measurement and refinement; default-off | May change or be removed across minor releases; documented in CHANGELOG.md. |
| **Internal** | Implementation details; no external compatibility guarantee | May change at any time without notice. |

---

## 1. Stable / Public Surface

The following interfaces and contracts form VerifyCI's authoritative public API:

### CLI Commands and Exit Semantics
- Primary CLI entry point: `verifyci` (and the `aci` compatibility alias).
- Commands: `init`, `ingest`, `verify-diff`, `stats`, `query`, `deps`, `run`, `verify-chain`, `serve`.
- **Exit Code Ladder**:
  - `0`: `PASS` (Verification succeeded; evidence and traces established).
  - `1`: `FAIL` (Verification failed; blocking check or invariant tripped).
  - `2`: `HUMAN_REVIEW` / `INCONCLUSIVE` (Uncertainty or inability to ground; escalated to human).
  - `3`: `INFRA_ERROR` / `TIMEOUT` (Infrastructure failure or task deadline exceeded; not a verdict).
- Output Formats:
  - Default text output.
  - `--format json`: Stable machine-readable Certificate and Report representation.
  - `--format sarif`: OASIS SARIF v2.1.0 standard representation.

### Frozen Contracts (`verifyci/contracts/`)
The schemas in `verifyci/contracts/` define the boundary between ingestion, storage, verification, and external tools:
- **`entity.Entity`**, **`entity.EntityType`**
- **`edge.Edge`**, **`edge.EdgeType`**
- **`event.Event`**, **`event.AttestationMetadata`**
- **`revision.Revision`**
- **`evidence.SourceChunk`**, **`evidence.ProvenanceEntry`**, **`evidence.EvidencePack`**
- **`verification_ir.Certificate`**, **`verification_ir.Premise`**, **`verification_ir.FileEvidence`**, **`verification_ir.ExecutionTrace`**, **`verification_ir.Conclusion`**
- **`verification_ir.CheckResult`**, **`verification_ir.VerificationReport`**, **`verification_ir.VerificationDecision`**, **`verification_ir.VerificationPolicy`**
- **`jsonio.to_json`**, **`jsonio.to_json_dict`**

*Breaking changes to frozen contracts require a formal contract amendment and a major version bump.*

### GitHub Action Integration (`action.yml`)
- Inputs: `path`, `db`, `base-ref`, `head-ref`, `format`, `output-file`, `fail-on-inconclusive`.
- Outputs: `status`, `rationale`, `exit-code`, `report-file`.

---

## 2. Experimental Surface

Features marked experimental are active research or opt-in capabilities undergoing evaluation:

- **Overlap Reranker** (`retrieval/reranker.py`): Opt-in via `verifyci query --rerank`. Default is off (measured net-negative on held-out benchmarks).
- **Ollama Local Embeddings** (`retrieval/dense.py`): Configured via `VERIFYCI_EMBEDDINGS=ollama[:model]`. Defaults to offline hash embeddings with zero server dependencies.
- **FastMCP HTTP Transport**: `verifyci serve --transport http`. Stdio transport is stable; HTTP binding is experimental.

---

## 3. Internal Implementation

The following modules are internal and not subject to compatibility guarantees:

- `verifyci/graph/builder.py`, `diagnostics.py`, and AST traversal internal ordering.
- Tree-sitter grammar parse-tree node extraction details in `ingestion/parser.py`.
- Transient types (`BDDSpec`, `NFR`, `Diff`, `CodeGraph`, `ExecutionContext`).
- Low-level SQLite schema tables and index definitions.

---

## Frozen Evidence & Benchmark Immutability

VerifyCI adheres to a strict scientific standard regarding empirical evidence:

1. **Frozen Benchmark Corpora Are Immutable**:
   - Corpora in `benchmarks/patch_corpus/`, `benchmarks/blast_corpus/`, `benchmarks/beir/`, `benchmarks/temporal_corpus/`, and `benchmarks/concurrency_corpus/` are frozen and pinned by SHA-256 hashes.
   - Ground-truth labels and oracles must never be modified retroactively to make an implementation appear passing.
2. **New Evidence Requires New Identifiers**:
   - Any new benchmark, ablation study, or capability measurement must receive a new directory and unique identifier (e.g., `cap009`).
3. **No Retroactive Retuning**:
   - Acceptance thresholds and gate definitions are declared before measurement runs, never tuned after seeing benchmark results.
