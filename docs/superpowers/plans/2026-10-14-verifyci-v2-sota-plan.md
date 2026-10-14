# VerifyCI v2.0: Ultra-Optimized Open-Source Architecture & Agent Execution Plan

**Date:** 2026-10-14  
**Target System:** `VerifyCI v2.0` (Clean-Slate Neuro-Symbolic & Cryptographic Verification Engine)  
**License & Philosophy:** 100% Open-Source, Local-First, Zero-API-Key Baseline, Vendor-Neutral Bring-Your-Own-AI (BYO-AI)  
**Required Agent Skills:** `.opencode/skills/vc-verifier-soundness`, `vc-blast-radius`, `vc-evidence-integrity`, `vc-performance`, `vc-gate-integrity`, `vc-release-verification`

---

## 1. Executive Summary & Architectural Shift

**VerifyCI v2.0** replaces v1's per-file Python AST walkers, split SQLite/JSON caches, and heuristic verification rules with a mathematically sound, sub-second verification engine. It is designed around a strict **Open-Source Zero-Trust Principle**:

1. **Zero-Key Deterministic Default:** Every core feature—polyglot symbol resolution, blast-radius computation, equality-saturation equivalence proofs, SMT counterexample generation, taint-tracked secret detection, and cryptographic git anchoring—runs 100% offline on standard CPU hardware with **zero external API keys**.
2. **Vendor-Neutral BYO-AI Protocol:** Users may optionally attach local open-weights models (`Ollama`, `llama.cpp`, `vLLM`, `ONNX`) or cloud API keys (`OpenRouter`, `OpenAI`, `Anthropic`, `Gemini`) for semantic intent compilation, mock-secret triage, and automated patch synthesis.
3. **AI Proposes, Symbolic Engine Disposes:** Neural models *never* directly pass or fail a CI gate. All AI judgments are bounded by **Split Conformal Prediction** and verified by **`egglog` (E-Graphs Modulo Theories)** and **Z3 SMT** before any verdict or auto-fix is emitted.

---

## 2. The 7 SOTA Protocol Pillars of VerifyCI v2.0

| Subsystem | v1 Legacy Implementation | v2.0 SOTA Protocol / Method | Quantitative Advantage |
| :--- | :--- | :--- | :--- |
| **1. Symbol & Call Resolution** | Single-pass AST walk + deferred string matching (`extractor.py`) | **`tree-sitter-stack-graphs`** + `XXH3` Content Hashing + Hybrid Type Cascade | Compositional per-file resolution in $< 5\text{ ms}$; zero full-repo re-indexing on edits. |
| **2. Incremental Memoization** | File-level cache invalidation (`incremental.py`, `graph_cache.py`) | **Salsa-Style Demand-Driven Early Cutoff** (`interface_hash` vs. `body_hash`) | Skips $80\%$ to $95\%$ of downstream blast-radius re-verification on private body edits. |
| **3. Relational & Equivalence Core** | Bespoke Python rule scripts (`call_swap.py`, `return_swap.py`, `deletion.py`) | **`egglog`** (Datalog + E-Graphs Modulo Theories) cascading into **Z3 SMT** | $100\times$ faster algebraic/refactoring equivalence proofs; wakes Z3 only on unresolved e-classes. |
| **4. CPU Embeddings & Vector Index** | Full sentence-transformer inference + 40MB+ JSON float caches (`dense.py`) | **`Model2Vec`** Static Distilled Embeddings + **`RaBitQ`** ($1\text{-bit}$ / $4\text{-bit}$ Error-Bounded Quantization) | $50\times$ smaller model footprint, $500\times$ faster CPU embedding, $32\times$ storage compression, $> 50\%$ fewer reranker calls. |
| **5. BYO-AI Structured Decoding** | Unconstrained or retry-based JSON prompting | **`llguidance`** ($\sim 50\text{ }\mu\text{s/token}$ Earley Context-Free Grammar Masking) + Token `logprobs` | Zero syntax retries; deterministic schema-locked output across any local or remote model. |
| **6. Model-Agnostic Calibration** | Hardcoded heuristic score thresholds (`policy.py`) | **Split Conformal Prediction** calibrated against held-out `cap` corpora | Guarantees a user-chosen false-pass error rate $\le \alpha$ regardless of which LLM the user brings. |
| **7. Cryptographic Provenance** | Local SQLite hash ledger (`memory/ledger.py`, `receipts.py`) | **OpenSSF `gittuf` Reference State Log (RSL)** + **RFC 8785 `in-toto` DSSE** | Forge-independent protection against branch/tag tampering, force-pushes, and replay attacks. |

---

## 3. Mathematical Foundations of the v2 Engine

### 3.1 Salsa-Style Early Cutoff Invariant
For every function node $f$ lowered to Unified Static Single Assignment ($\text{U-SSA}$), VerifyCI v2 computes two cryptographic digests using $\text{BLAKE3}$:
$$H_{\text{interface}}(f) = \text{BLAKE3}\left(\text{CanonicalSig}(f) \parallel \text{PuritySummary}(f) \parallel \text{TaintFlowSummary}(f) \parallel \text{RaisedExceptions}(f)\right)$$
$$H_{\text{body}}(f) = \text{BLAKE3}\left(\text{NormalizedUSSA}(f)\right)$$

When a commit mutates $f \rightarrow f'$:
* If $H_{\text{body}}(f) = H_{\text{body}}(f')$, verification is a $O(1)$ cache hit.
* If $H_{\text{body}}(f) \neq H_{\text{body}}(f')$ but $H_{\text{interface}}(f) = H_{\text{interface}}(f')$, only $f'$ is re-verified locally; all transitive callers $c \in \text{Callers}^+(f)$ retain their memoized verdicts.

### 3.2 Two-Stage Symbolic Verification (`egglog` $\rightarrow$ Z3 SMT)
Given a pre-patch function $F_{\text{base}}(\vec{x})$ and post-patch function $F_{\text{head}}(\vec{x})$:
1. **Stage 1 (Equality Saturation in `egglog`):** Both $F_{\text{base}}$ and $F_{\text{head}}$ are inserted into a unified e-graph alongside semantics-preserving rewrite rules $\mathcal{R}$ (commutativity, guard de-Morgan laws, variable un-shadowing, dead-store elimination). If saturation proves:
   $$\text{e-class}(F_{\text{base}}(\vec{x})) = \text{e-class}(F_{\text{head}}(\vec{x}))$$
   then $F_{\text{base}} \equiv F_{\text{head}}$ is proven in $< 1\text{ ms}$ with Verdict `PROVEN_EQUIVALENT`.
2. **Stage 2 (Z3 SMT Counterexample Extraction):** If the output e-classes diverge and violate a structural Datalog rule (such as `call_swap`, `return_swap`, `guard_inversion`, or an intent assertion $\Phi_{\text{intent}}$), `vc-smt` encodes the unresolved e-graph slice into Z3 and solves:
   $$\exists \vec{x} : \text{Precond}(\vec{x}) \land \neg\Phi_{\text{intent}}(\vec{x}, F_{\text{base}}(\vec{x}), F_{\text{head}}(\vec{x}))$$
   If `SAT`, the concrete assignment $\vec{x}^*$ is extracted from `solver.model()` as an irrefutable `CounterexampleWitness`.

### 3.3 `RaBitQ` Error-Bounded Retrieval Pruning
For a $D$-dimensional normalized code embedding $\vec{v}$ and query vector $\vec{q}$, `RaBitQ` stores a $1\text{-bit}$ quantized vector $\bar{v} \in \{-1/\sqrt{D}, +1/\sqrt{D}\}^D$ plus a scalar correction factor, yielding an unbiased inner-product estimator $\hat{s}(\vec{q}, \vec{v})$ with a theoretical error bound $\epsilon(\vec{q}, \vec{v})$ such that:
$$\mathbb{P}\left(\left|\langle \vec{q}, \vec{v} \rangle - \hat{s}(\vec{q}, \vec{v})\right| \le \epsilon(\vec{q}, \vec{v})\right) > 0.9999$$

During two-stage retrieval reranking (`reranker.py`), if the $k$-th best exact reranker score seen so far is $S_k^*$, any candidate $i$ satisfying:
$$\hat{s}(\vec{q}, \vec{v}_i) + \epsilon(\vec{q}, \vec{v}_i) < S_k^*$$
is pruned immediately without invoking the Cross-Encoder or BYO-AI judge.

### 3.4 Split Conformal Prediction for BYO-AI Calibration
To make VerifyCI v2 agnostic to poorly calibrated user models, let $\mathcal{D}_{\text{cal}} = \{(x_i, y_i)\}_{i=1}^n$ be the held-out VerifyCI calibration benchmark (`cap002_heldout`, `cap011`). For any user-configured model $M$, define the non-conformity score $R_i = 1 - \hat{p}_M(y_i \mid x_i)$. For a user-specified maximum false-pass risk $\alpha \in (0, 1)$ (default $\alpha = 0.02$), we compute the conformal quantile:
$$\hat{q}_{1-\alpha} = \text{Quantile}\left(\{R_1, \dots, R_n, \infty\},\; \frac{\lceil (n + 1)(1 - \alpha) \rceil}{n}\right)$$

At CI runtime on a new diff $x_{\text{new}}$, the prediction set is $\mathcal{C}(x_{\text{new}}) = \{y : 1 - \hat{p}_M(y \mid x_{\text{new}}) \le \hat{q}_{1-\alpha}\}$.
* If $|\mathcal{C}(x_{\text{new}})| = 1$, the system accepts the fast System 1 judgment with finite-sample coverage guarantee $\mathbb{P}(y_{\text{true}} \in \mathcal{C}(x_{\text{new}})) \ge 1 - \alpha$.
* If $|\mathcal{C}(x_{\text{new}})| > 1$ (ambiguous) or `"defect" \in \mathcal{C}(x_{\text{new}})$, VerifyCI **abstains** from the neural shortcut and escalates the diff to the deterministic `egglog` + Z3 engine.

---

## 4. Target Repository & Module Topology (`verifyci_v2`)

```text
verifyci/
├── pyproject.toml                        # Python 3.12+, uv workspace, ruff, strict mypy
├── .verifyci/
│   ├── config.toml                       # Zero-key defaults + BYO-AI provider settings
│   └── conformal_calibration.json        # Per-model empirical quantiles (q_hat)
├── verifyci_v2/
│   ├── contracts/                        # RFC 8785 JCS + msgspec zero-copy contracts
│   │   ├── canonical.py                  # RFC 8785 JCS serializer + BLAKE3/XXH3 hashing
│   │   ├── ssa_ir.py                     # U-SSA, StackGraph, CFG, DFG, and Polyglot schemas
│   │   ├── ai_protocol.py                # Vendor-neutral Judge, Synthesizer & Conformal schemas
│   │   └── attestation.py                # in-toto DSSE + gittuf RSL + SARIF v2.1.0 contracts
│   ├── ingestion/                        # Compositional Polyglot Front-End
│   │   ├── stack_graphs.py               # tree-sitter-stack-graphs incremental symbol resolver
│   │   ├── ssa_lower.py                  # Tree-sitter CST -> Unified SSA + Phi nodes
│   │   ├── polyglot_bridge.py            # Python ctypes/pybind11 <-> C & FastAPI/Flask <-> TS
│   │   └── salsa_cutoff.py               # H_interface vs H_body early-cutoff memoizer
│   ├── store/                            # Single-Artifact Arrow Storage (.verifyci/store.vc2)
│   │   ├── duckdb_cpg.py                 # Code Property Graph + commit snapshot isolation
│   │   ├── model2vec_embed.py            # 500x faster static CPU code embeddings
│   │   └── rabitq_index.py               # 1-bit/4-bit RaBitQ vector index + BM25 + coverage weights
│   ├── symbolic/                         # Deterministic Formal Verification Engine
│   │   ├── egglog_engine.py              # Equality saturation + Datalog reachability/taint rules
│   │   ├── z3_prover.py                  # Path-sensitive SMT solver & CounterexampleWitness extractor
│   │   └── secrets_taint.py              # Entropy + DFG taint-to-sink + opt-in live token probe
│   ├── neural/                           # Vendor-Neutral BYO-AI & Conformal Layer
│   │   ├── adapters.py                   # Deterministic (default), LocalONNX, Ollama, OpenAICompat
│   │   ├── grammar_mask.py               # llguidance CFG schema enforcement + logprobs extractor
│   │   ├── conformal.py                  # Split conformal calibration & abstention gate
│   │   └── cegis_repair.py               # Z3-guided counterexample patch synthesis (`vc2 fix`)
│   ├── sandbox/                          # Safe Extensibility
│   │   └── wasm_runner.py                # Wasmtime Component Model host with CPU fuel budgets
│   ├── provenance/                       # Forge-Independent Security
│   │   ├── dsse_intoto.py                # Keyless Sigstore / Ed25519 DSSE envelope signer
│   │   └── gittuf_rsl.py                 # Tamper-evident Reference State Log + refs/notes/verifyci
│   └── interface/                        # Unified CLI & Agent Daemon
│       ├── cli.py                        # `vc2 check`, `vc2 prove`, `vc2 fix`, `vc2 calibrate`, `vc2 mcp`
│       └── fastmcp_daemon.py             # Single hot-reloading <20ms MCP server with fs-watcher
└── benchmarks/                           # Manifest-pinned capability suites (cap001 - cap013)
```

---

## 5. Reference Specification: Vendor-Neutral BYO-AI + Conformal Gate

Below is the reference contract for `verifyci_v2/neural/conformal.py` and `verifyci_v2/contracts/ai_protocol.py` that enables any user-supplied model to act as a mathematically bounded System 1 judge:

```python
from __future__ import annotations
import math
from typing import Protocol, Sequence
import msgspec


class ConformalProfile(msgspec.Struct, frozen=True):
    model_id: str
    weights_or_endpoint_hash: str
    alpha: float
    sample_size: int
    q_hat: float  # Empirical (1 - alpha) non-conformity quantile


class CalibratedDecision(msgspec.Struct, frozen=True):
    prediction_set: tuple[str, ...]
    top_choice: str
    raw_probability: float
    abstained: bool        # True if |prediction_set| != 1 -> triggers egglog/Z3 escalation
    escalate_to_smt: bool


def compute_conformal_quantile(non_conformity_scores: Sequence[float], alpha: float = 0.02) -> float:
    """Computes the finite-sample split conformal quantile q_hat for target error rate alpha."""
    n = len(non_conformity_scores)
    if n == 0:
        return 1.0
    sorted_scores = sorted(non_conformity_scores)
    rank = math.ceil((n + 1) * (1.0 - alpha))
    if rank > n:
        return 1.0
    return float(sorted_scores[rank - 1])


def evaluate_with_conformal_gate(
    class_probabilities: dict[str, float],
    profile: ConformalProfile,
    safe_label: str = "none",
) -> CalibratedDecision:
    """Applies the conformal threshold q_hat to decide whether to fast-pass or escalate to Z3."""
    prediction_set = tuple(
        label for label, prob in sorted(class_probabilities.items())
        if (1.0 - prob) <= profile.q_hat
    )
    top_choice = max(class_probabilities.items(), key=lambda kv: kv[1])[0]
    raw_prob = class_probabilities[top_choice]

    # Abstain if the prediction set is empty, contains multiple plausible classes,
    # or includes any non-safe defect class.
    abstained = len(prediction_set) != 1
    escalate = abstained or (prediction_set[0] != safe_label)

    return CalibratedDecision(
        prediction_set=prediction_set,
        top_choice=top_choice,
        raw_probability=raw_prob,
        abstained=abstained,
        escalate_to_smt=escalate,
    )
```

---

## 6. Phased Autonomous Agent Execution Plan

### Milestone 0: Repo Hygiene, RFC 8785 Contracts & Fixture Deduplication
**Goal:** Eliminate v1 technical debt, deduplicate benchmark fixtures, and establish the v2 canonical contract layer.

* **Step 0.1 (Artifact & Fixture Cleanup):**
  * Replace duplicated modules in `benchmarks/latency/fixture/` (`extractor.py`, `graph_store.py`, `intent_align.py`, `provider.py`, `env.py`) with thin re-exports of core package modules so benchmarks never drift from production code.
  * Move `benchmarks/beir/embedding_cache_nomic_embed_text.json` to lazy on-demand generation or Git LFS via `.gitattributes`.
  * Pin `FROM python:3.12-slim` in `benchmarks/patch_corpus/base/Dockerfile` to an immutable `@sha256` digest.
* **Step 0.2 (Canonical Contracts):**
  * Implement `verifyci_v2/contracts/canonical.py` using `msgspec` and RFC 8785 JSON Canonicalization Scheme (JCS) with `XXH3` (fast file fingerprinting) and `BLAKE3` (cryptographic Merkle identities).
  * Implement `verifyci_v2/contracts/ai_protocol.py` and `verifyci_v2/neural/conformal.py`.
* **Verification Gate M0:**
  ```bash
  uv run pytest tests/contracts/ tests/evaluation/test_latency_repro.py tests/evaluation/test_optimizations_equivalence.py -v
  ```

---

### Milestone 1: Compositional Stack Graphs, U-SSA & Salsa Early Cutoff
**Goal:** Achieve $< 5\text{ ms}$ incremental symbol resolution and cross-language call-graph construction.

* **Step 1.1 (`stack_graphs.py` & `ssa_lower.py`):**
  * Integrate `tree-sitter` and scope-graph resolution in `verifyci_v2/ingestion/stack_graphs.py` for Python, TypeScript/JS, C/C++, Rust, and Go.
  * Lower CST function bodies into `U-SSA` basic blocks with explicit $\phi$-nodes, Control Flow (`CFG`), and Data Flow (`DFG`) def-use edges in `ssa_lower.py`.
* **Step 1.2 (`polyglot_bridge.py`):**
  * Automatically link Python `ctypes`/`cffi`/`pybind11` declarations to C function definitions (`samples/test-repo/src/util.c`) and link Python `@app.route`/`@router` endpoints (`benchmarks/patch_real/cap005/base/src/api/routes.py`) to TypeScript `fetch()` callers.
* **Step 1.3 (`salsa_cutoff.py`):**
  * Compute $H_{\text{interface}}(f)$ and $H_{\text{body}}(f)$ for every function node and short-circuit downstream blast-radius invalidation whenever $H_{\text{interface}}(f)$ is invariant across a diff.
* **Verification Gate M1:**
  ```bash
  uv run pytest tests/ingestion/ tests/graph/ -v
  ```

---

### Milestone 2: DuckDB Property Graph + `Model2Vec` + `RaBitQ` Index
**Goal:** Replace SQLite and heavy PyTorch embeddings with an Arrow-native store, $500\times$ faster static CPU embeddings, and error-bounded $1\text{-bit}$ vector search.

* **Step 2.1 (`duckdb_cpg.py`):**
  * Store `ssa_nodes`, `cfg_edges`, `dfg_edges`, `call_edges`, and `salsa_digests` in DuckDB with zero-copy Arrow scans and commit-scoped temporal views (accelerating `cap006` temporal replay).
* **Step 2.2 (`model2vec_embed.py` & `rabitq_index.py`):**
  * Prepend each function's structural graph header (callers, callees, mutated state, raised exceptions) to its normalized code text.
  * Embed code chunks on CPU using `Model2Vec` static embeddings (or any user-configured `EmbeddingProviderProtocol`).
  * Quantize vectors using `RaBitQ` ($1\text{-bit}$ storage + residual norm bound) alongside a BM25 inverted index.
  * Ingest optional `coverage.xml` / `.coverage` line-execution frequencies to weight blast-radius traversal edges dynamically (`scripts/ci_test_selector.py`).
* **Verification Gate M2:**
  ```bash
  uv run pytest tests/storage/ tests/retrieval/ tests/performance/test_scale_100k.py -v
  ```

---

### Milestone 3: `egglog` Equality Saturation + Z3 SMT Counterexample Prover
**Goal:** Replace heuristic AST checkers with formal relational Datalog, e-graph equality saturation, and Z3 counterexample proofs.

* **Step 3.1 (`egglog_engine.py`):**
  * Encode global graph invariants in `egglog`:
    * **Unsafe Deletion (`cap003a`):** Reachability of deleted symbols from live entrypoints or dynamic exports.
    * **Concurrency Race & Lock Order (`cap008`):** Shared state mutation across concurrent/async entrypoints without a common dominating lock.
    * **Algebraic Refactoring Equivalence:** Prove $F_{\text{base}} \equiv F_{\text{head}}$ via equality saturation rewrite rules.
* **Step 3.2 (`z3_prover.py`):**
  * For diffs where `egglog` cannot unify the pre-patch and post-patch return/effect e-classes—or where `call_swap`, `return_swap`, `guard_inversion`, or `shadow_assign` candidates are detected—lower the diverging U-SSA slice to `z3-solver`.
  * Extract concrete input counterexamples $\vec{x}^*$ from `solver.model()` into a deterministic `CounterexampleWitness`.
* **Step 3.3 (`secrets_taint.py`):**
  * Combine Shannon entropy + multi-pass decoding (`verifyci/secrets/`) with DFG taint-path tracking from credential sources to logging/network sinks, plus opt-in zero-side-effect live token liveness checks (`--verify-live`).
* **Verification Gate M3:**
  ```bash
  uv run pytest tests/verification/ tests/adversarial/ -v
  ```

---

### Milestone 4: BYO-AI Adapters, `llguidance` Masking, Conformal Calibration & CEGIS `--fix`
**Goal:** Connect optional local/remote AI models with zero vendor lock-in, guaranteed schema compliance, mathematical error bounds, and Z3-verified auto-repair.

* **Step 4.1 (`adapters.py` & `grammar_mask.py`):**
  * Implement 4 zero-lock-in providers: `deterministic` (default, zero AI), `local-onnx`, `ollama`, and `openai-compatible` (via pure `httpx`).
  * Enforce strict JSON/CFG schemas via `llguidance` for local models and extract token `logprobs` to populate `BooleanJudgment`, `CategoricalChoice`, and `OrdinalScore`.
  * Pass all egress payloads through `verifyci/secrets/redaction.py` prior to any remote API call.
* **Step 4.2 (`vc2 calibrate` Command):**
  * Add `verifyci calibrate` to run the user's configured BYO-AI judge against held-out benchmark slices (`cap002_heldout`, `cap011`) and write `.verifyci/conformal_calibration.json` containing $\hat{q}_{1-\alpha}$.
* **Step 4.3 (`cegis_repair.py` — `vc2 fix`):**
  * Feed the failing function's U-SSA slice + Z3 `CounterexampleWitness` to `GenerativeSynthesizerProtocol`.
  * Parse the candidate patch in-memory, run `egglog` + `z3_prover.py` to verify the counterexample is eliminated (`UNSAT`) without introducing new unresolved references, and attach the verified diff to the SARIF v2.1.0 `fixes` array.
* **Verification Gate M4:**
  ```bash
  uv run pytest tests/evaluation/ tests/export/test_sarif_export.py -v
  ```

---

### Milestone 5: Single FastMCP Daemon, Wasm Sandbox & `gittuf` RSL Provenance
**Goal:** Unify agent interfaces, sandbox third-party checkers in WebAssembly, and anchor tamper-evident receipts in Git.

* **Step 5.1 (`fastmcp_daemon.py`):**
  * Consolidate `verifyci/interface/mcp_server.py` and `fastmcp_server.py` into a single stateful FastMCP daemon with a background filesystem watcher (`watchfiles`) keeping the DuckDB/RaBitQ index hot for $< 20\text{ ms}$ agent queries.
  * Update all 12 agent skills in `.opencode/skills/` to use the unified toolset.
* **Step 5.2 (`wasm_runner.py`):**
  * Execute custom repository checkers as sandboxed WebAssembly components (`wasmtime`) with deterministic CPU fuel budgets (`verifyci/interface/limits.py` replacement) and zero filesystem/network access.
* **Step 5.3 (`dsse_intoto.py` & `gittuf_rsl.py`):**
  * Emit RFC 8785 canonical `in-toto` v1.0 attestations signed via Ed25519 or keyless Sigstore OIDC.
  * Record the attestation digest and branch state in a `gittuf`-compatible Reference State Log (`refs/gittuf/reference-state-log`) and `refs/notes/verifyci` so any CI runner can verify commit lineage offline without a shared SQLite database.
* **Verification Gate M5:**
  ```bash
  uv run pytest tests/integration/test_fastmcp.py tests/integration/test_ledger_anchor.py .opencode/skills/tests/test_vc_acceptance.py -v
  ```

---

## 7. Capability Benchmark Adjudication Matrix (`cap001` – `cap013`)

Before tagging the v2.0 release, the autonomous agent must execute the full adjudication suite (`scripts/adjudicate_cap.py`) and meet or exceed the following targets across all 13 benchmark corpora:

| Capability ID | Benchmark Suite | Primary v2.0 Engine | Acceptance Metric Target |
| :--- | :--- | :--- | :--- |
| **`cap001`** | `benchmarks/beir/` | `Model2Vec` + `RaBitQ` + Conformal Reranker | $\text{nDCG@10} \ge \text{v1 baseline} + 6\%$, latency $< 15\text{ ms}$ |
| **`cap002`** | `benchmarks/patch_corpus/` | `egglog` + `z3_prover.py` | $100\%$ precision on held-out semantic defects (`0` false passes) |
| **`cap002b`** | `benchmarks/secret_corpus/cap002b/` | `secrets_taint.py` + Conformal Mock Triage | $0.0\%$ false-positive rate on test fixtures, $100\%$ recall |
| **`cap003`** | `benchmarks/blast_corpus/` | `stack_graphs.py` + `salsa_cutoff.py` | $100\%$ tail-seeding recall, $\ge 80\%$ reduction in unchanged-interface traversal |
| **`cap003a`** | `benchmarks/removal_corpus/cap003a/` | `egglog` Datalog Reachability | $100\%$ precision on unsafe deletions & dynamic exports |
| **`cap004`** | `benchmarks/call_semantics_corpus/cap004/` | `ssa_lower.py` + `z3_prover.py` | Catches $100\%$ of aliased call/argument/return swaps |
| **`cap005`** | `benchmarks/patch_real/cap005/` | Full Neuro-Symbolic Loop + `cegis_repair.py` | $100\%$ verdict parity + $\ge 85\%$ Z3-verified auto-fix synthesis rate |
| **`cap006`** | `benchmarks/temporal_corpus/cap006/` | `duckdb_cpg.py` Snapshot Isolation | $10\times$ faster `as_of` replay with $100\%$ bit-for-bit determinism |
| **`cap007`** | `benchmarks/retrieval_corpus/cap007/` | `RaBitQ` $1\text{-bit}$ Index + Error-Bound Pruning | P99 query latency $< 25\text{ ms}$ at 100k+ graph nodes |
| **`cap008`** | `benchmarks/concurrency_corpus/cap008/` | `egglog` Lock-Order & Async Mutation Rules | $100\%$ precision/recall on r1 capability concurrency corpus |
| **`cap009`** | `benchmarks/diff_impact_corpus/cap009/` | `polyglot_bridge.py` + Coverage Weighting | Exact cross-module & cross-language diff impact ranking |
| **`cap010`** | `benchmarks/retrieval_generalization/cap010/` | Neighborhood-Header `Model2Vec` + `RaBitQ` | Zero generalization drop across unseen repository topologies |
| **`cap011`** | `benchmarks/secret_heldout/cap011/` | DFG Taint-to-Sink + Multi-Layer Decoder | $100\%$ F1 on held-out obfuscated secrets |
| **`cap012`** | `benchmarks/repo_perf/cap012/` | `XXH3` + `stack_graphs` + Salsa Cutoff | Incremental cold-to-warm speedup $\ge 15\times$ |
| **`cap013`** | `benchmarks/robustness/cap013/` | `egglog` E-Graph Normalization + Z3 | $100\%$ mutation invariance under semantics-preserving AST perturbations |