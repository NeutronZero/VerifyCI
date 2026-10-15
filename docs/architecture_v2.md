# VerifyCI v2.0: System Architecture Plan & Technical Specification

**Status:** Partially Implemented — see `docs/architecture_v2_gap_audit.md` (v2.0 Clean-Slate) 
 
**Date:** 2026-10-14  
**Replaces:** `docs/architecture.md` (v1.x)  
**Design Paradigm:** Local-First, Neuro-Symbolic, Cryptographically Attested, Vendor-Neutral BYO-AI

---

## 1. Architectural Vision & Core Invariants

**VerifyCI v2.0** transitions the system from a collection of per-file Python AST walkers and split SQLite/JSON caches into a unified **Incremental Relational, Symbolic Proof, and Cryptographic Attestation Engine**.

The architecture enforces five non-negotiable invariants:

1. **Zero-Key Deterministic Baseline:** All core verification gates—polyglot symbol resolution, blast-radius analysis, equality-saturation equivalence proofs, SMT counterexample extraction, taint-tracked secret detection, and cryptographic git anchoring—execute 100% offline on standard CPU hardware with **zero external API keys**.
2. **Neuro-Symbolic Separation of Powers ("AI Proposes, Symbolic Engine Disposes"):** Optional user-supplied AI models (local `ONNX`, `Ollama`, `vLLM`, or cloud APIs) *never* directly pass or fail a CI gate. Neural outputs are constrained by **`llguidance` context-free grammars**, bounded by **Split Conformal Prediction**, and formally proven by **`egglog` + Z3 SMT** before any verdict or auto-fix is emitted.
3. **Sub-Second Compositional Reactivity:** File ingestion, symbol resolution, and verification are modeled as pure, demand-driven memoized queries keyed by `XXH3` and `BLAKE3` digests with **Salsa-style early cutoff**.
4. **Single-Artifact Zero-Copy Storage:** All graph topologies, Static Single Assignment ($\text{U-SSA}$) blocks, temporal commit snapshots, BM25 lexical indexes, and $1\text{-bit}$ `RaBitQ` quantized vectors reside in a unified, Arrow-native DuckDB store (`.verifyci/store.vc2`).
5. **Forge-Independent Provenance:** Verification receipts are canonicalized via **RFC 8785 (JCS)**, wrapped in **`in-toto` v1.0 DSSE envelopes**, and anchored into an **OpenSSF `gittuf` Reference State Log (RSL)** inside the Git repository.

---

## 2. High-Level System Topology & Dataflow

```text
+-----------------------------------------------------------------------------------+
|                        L1: INGRESS & STATEFUL AGENT DAEMON                        |
|   CLI (`vc2 check/prove/fix`)  |  Hot FastMCP Daemon (<20ms)  |  SARIF v2.1 / CI  |
+-----------------------------------------+-----------------------------------------+
                                          | (Zero-Copy Arrow / msgspec JCS)
                                          v
+-----------------------------------------------------------------------------------+
|                   L2: DEMAND-DRIVEN INCREMENTAL ENGINE (SALSA)                    |
|     XXH3 File Fingerprinting  -->  H_body vs. H_interface Early-Cutoff Gate       |
+-------------------+-----------------------------+---------------------------------+
                    |                             |
                    v                             v
+-----------------------------------+   +-------------------------------------------+
|   L3: POLYGLOT FRONT-END          |   |   L4: UNIFIED ARROW STORE (.vc2)          |
| - tree-sitter-stack-graphs        |   | - DuckDB Code Property Graph (CPG)        |
| - CST -> Unified SSA (U-SSA)      |-->| - Temporal Commit Snapshot Views (cap006) |
| - Intraprocedural CFG & DFG       |   | - Model2Vec Static CPU Embeddings         |
| - Polyglot Bridge (FFI & HTTP)    |   | - RaBitQ 1-Bit Error-Bounded Vector Index |
+-----------------------------------+   +-------------------+-----------------------+
                                                            |
                    +---------------------------------------+
                    |
                    v
+-----------------------------------------------------------------------------------+
|                    L5: NEURO-SYMBOLIC VERIFICATION PIPELINE                       |
|                                                                                   |
|  +-------------------------------+         +-----------------------------------+  |
|  | Stage A: BYO-AI System 1 Gate | Abstain | Stage B: Symbolic Proof Engine    |  |
|  | - Deterministic / ONNX / LLM  |-------->| 1. egglog Equality Saturation     |  |
|  | - llguidance Grammar Masking  |   or    |    & Datalog Reachability/Taint   |  |
|  | - Split Conformal Calibration | Defect  | 2. Z3 SMT Path Solver & Witness   |  |
|  +-------------------------------+         +-----------------+-----------------+  |
|                                                              |                    |
|                                                              v (If SAT / Defect)  |
|                                            +-----------------------------------+  |
|                                            | Stage C: CEGIS Auto-Repair Loop   |  |
|                                            | - Pre-Egress Secret Redaction     |  |
|                                            | - Candidate Fix -> Z3 Re-Verify   |  |
|                                            +-----------------+-----------------+  |
+--------------------------------------------------------------|--------------------+
                                                               |
                                                               v
+-----------------------------------------------------------------------------------+
|                L6: WASM SANDBOX & CRYPTOGRAPHIC PROVENANCE LAYER                  |
|  Wasmtime Component Checkers  |  RFC 8785 in-toto DSSE  |  gittuf RSL Git Anchor  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Layer-by-Layer Technical Architecture

### 3.1 Layer 1: Unified Ingress & Stateful FastMCP Daemon (`verifyci_v2/interface/`)
In v1, maintaining separate `mcp_server.py` and `fastmcp_server.py` modules created transport duplication and cold-start overhead.
* **Single Stateful Daemon (`fastmcp_daemon.py`):** Exposes all verification, blast-radius, retrieval, and repair capabilities over the Model Context Protocol (stdio and SSE/HTTP).
* **Background Filesystem Watcher (`watchfiles`):** Monitors the working tree for file saves, incrementally updating the in-memory `stack-graphs` and DuckDB CPG tables in the background so agent tool invocations (`vc_blast_radius`, `vc_prove_diff`, `vc_query_graph`, `vc_triage_secrets`) complete in $< 20\text{ ms}$.
* **Strict Ingress & Budget Enforcement:** Replaces `verifyci/interface/ingress.py` and `limits.py` with token-bucket rate limiters, payload size bounds, and per-query wall-clock/CPU fuel budgets.

---

### 3.2 Layer 2: Compositional Polyglot Front-End (`verifyci_v2/ingestion/`)

#### A. Incremental Name Resolution (`stack_graphs.py`)
Replaces v1's deferred string matching (`tests/graph/test_deferred_resolution.py`) with **`tree-sitter-stack-graphs`**:
* Constructs per-file scope graphs with *push-symbol* and *pop-symbol* nodes for Python, TypeScript/JavaScript, C/C++, Rust, and Go.
* **Compositional Stitching:** Scope graphs are computed per file in isolation ($< 5\text{ ms/file}$). Cross-file imports and method receivers are resolved by concatenating path fragments at query time—eliminating full-repository re-indexing when a single file is edited.

#### B. Unified Static Single Assignment Lowering (`ssa_lower.py`)
To catch aliased bugs that evade shallow AST rules (`call_swap`, `return_swap`, `shadow_assign`), every function CST is lowered into language-agnostic **$\text{U-SSA}$**:
* Every local variable assignment creates a versioned symbol $v_0, v_1, \dots, v_k$.
* Branch merges insert explicit $\phi(v_i, v_j)$ nodes.
* Generates three explicit edge sets per function:
  1. **`CFG_EDGE`:** Basic block control transfers labeled with branch predicates ($P$, $\neg P$, or `exception`).
  2. **`DFG_EDGE`:** Direct def-use dataflow dependencies ($v_i \xrightarrow{\text{def-use}} v_j$).
  3. **`SUMMARY_EDGE`:** Interprocedural parameter-to-return and parameter-to-sink taint summaries.

#### C. Cross-Language Polyglot Bridge (`polyglot_bridge.py`)
Connects multi-language boundaries into a single unified call graph:
* **FFI Bridge (`Python` $\leftrightarrow$ `C/C++`):** Detects `ctypes.CDLL`, `cffi.FFI`, and `pybind11` module bindings and links Python call sites directly to C function definitions (e.g., `samples/test-repo/src/util.c`).
* **REST/RPC Route Bridge (`TypeScript/JS` $\leftrightarrow$ `Python`):** Matches FastAPI/Flask route decorators (`@app.route`, `@router.get` in `src/api/routes.py`) with TypeScript/JavaScript `fetch()` / `axios` client paths using normalized URL path templates.

---

### 3.3 Layer 3: Demand-Driven Incremental Engine (`salsa_cutoff.py`)

VerifyCI v2 models verification as a demand-driven query DAG inspired by the **Salsa** incremental computation framework.

For every function $f$, two $\text{BLAKE3}$ digests are maintained:
1. **Body Digest:**
   $$H_{\text{body}}(f) = \text{BLAKE3}\left(\text{CanonicalJCS}(\text{USSA}(f))\right)$$
2. **Interface Digest:**
   $$H_{\text{interface}}(f) = \text{BLAKE3}\left(\text{Signature}(f) \parallel \text{Purity}(f) \parallel \text{TaintSummary}(f) \parallel \text{ExceptionSet}(f)\right)$$

#### Early-Cutoff State Machine
When a file edit mutates $f \rightarrow f'$:
* **Case 1 ($H_{\text{body}}(f) = H_{\text{body}}(f')$):** Whitespace or comment-only change. Immediate $O(1)$ cache hit; zero verification work performed.
* **Case 2 ($H_{\text{body}}(f) \neq H_{\text{body}}(f') \land H_{\text{interface}}(f) = H_{\text{interface}}(f')$):** Internal implementation edit that preserves the external contract. VerifyCI re-verifies $f'$ locally (`egglog` + Z3) and **cuts off propagation**—skipping re-verification of the $N$ transitive callers $\text{Callers}^+(f)$.
* **Case 3 ($H_{\text{interface}}(f) \neq H_{\text{interface}}(f')$):** Public signature, side-effect, or taint contract changed. Invalidation propagates along incoming `CALLS` and `POLYGLOT_BRIDGE` edges to re-verify affected callers.

---

### 3.4 Layer 4: Unified Arrow-Native Storage & `RaBitQ` Index (`verifyci_v2/store/`)

All persistence is consolidated into a single embedded **DuckDB + Apache Arrow** database file (`.verifyci/store.vc2`), replacing `graph_store.py`, `graph_cache.py`, and external JSON float caches.

#### A. Relational Code Property Graph Schema (`duckdb_cpg.py`)
```sql
CREATE TABLE commits (
    commit_sha TEXT PRIMARY KEY,
    parent_sha TEXT,
    rsl_entry_hash TEXT NOT NULL,
    ingested_at_epoch BIGINT NOT NULL
);

CREATE TABLE function_nodes (
    node_uid TEXT PRIMARY KEY,          -- BLAKE3(repo_id || qualified_name || H_body)
    qualified_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    language TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    h_interface BLOB NOT NULL,
    h_body BLOB NOT NULL,
    ussa_payload BLOB NOT NULL          -- Zstd-compressed msgspec U-SSA IR
);

CREATE TABLE commit_node_map (
    commit_sha TEXT NOT NULL,
    node_uid TEXT NOT NULL,
    PRIMARY KEY (commit_sha, node_uid)
);

CREATE TABLE cpg_edges (
    edge_uid TEXT PRIMARY KEY,
    src_node_uid TEXT NOT NULL,
    dst_node_uid TEXT NOT NULL,
    edge_kind TEXT NOT NULL,            -- 'CALLS' | 'CFG' | 'DFG' | 'FFI_BRIDGE' | 'HTTP_BRIDGE'
    static_weight DOUBLE DEFAULT 1.0,
    coverage_hit_freq DOUBLE DEFAULT 0.0
);
```
* **Instant Temporal Replay (`cap006`):** Querying the repository graph `AS OF` any historical commit is a single indexed join against `commit_node_map`, running $10\times$ faster than v1 snapshot reconstruction with 100% bit-for-bit determinism.

#### B. `Model2Vec` CPU Embeddings & `RaBitQ` Error-Bounded Search (`rabitq_index.py`)
1. **Neighborhood-Enriched Representation:** Before embedding a function node, VerifyCI prepends a canonical structural header:
   ```text
   [LANG: python] [SIG: def charge_card(user_id: int, amount: Decimal) -> Receipt]
   [CALLERS: checkout_flow, retry_invoice] [CALLEES: stripe_charge, audit_log]
   [MUTATES: db.transactions] [RAISES: PaymentDeclinedError]
   ```
2. **Static Distilled CPU Embeddings (`model2vec_embed.py`):** Uses `Model2Vec` static token embeddings by default ($500\times$ faster than full transformer inference on CPU, $< 30\text{ MB}$ RAM), while supporting any user-configured `EmbeddingProviderProtocol`.
3. **`RaBitQ` Quantization & Pruning:**
   * Each $D$-dimensional normalized vector $\vec{v} \in \mathbb{R}^D$ is quantized into a $1\text{-bit}$ binary string $\bar{v} \in \{-1/\sqrt{D}, +1/\sqrt{D}\}^D$ plus a 32-bit float correction factor.
   * For any query vector $\vec{q}$, `RaBitQ` computes the estimated inner product $\hat{s}(\vec{q}, \vec{v}_i)$ and an analytical upper bound $\epsilon(\vec{q}, \vec{v}_i)$ in a single SIMD bitwise `XOR` + `POPCNT` pass.
   * Any candidate where $\hat{s}(\vec{q}, \vec{v}_i) + \epsilon(\vec{q}, \vec{v}_i) < S_k^*$ (the $k$-th best exact reranker score) is pruned immediately without invoking the Cross-Encoder or BYO-AI judge.

---

### 3.5 Layer 5: Two-Stage Symbolic Verification Core (`verifyci_v2/symbolic/`)

#### Stage 1: `egglog` Equality Saturation & Relational Datalog (`egglog_engine.py`)
VerifyCI v2 embeds **`egglog`** to unify Datalog reachability queries with e-graph equality saturation:
* **Fast Refactoring Equivalence:** Given pre-patch $F_{\text{base}}$ and post-patch $F_{\text{head}}$, both $\text{U-SSA}$ graphs are loaded into an `egglog` e-graph with semantics-preserving rewrite rules (boolean De Morgan identities, commutative arithmetic, dead-store elimination, variable un-shadowing). If $F_{\text{base}}$ and $F_{\text{head}}$ saturate into the same equivalence class ($\text{e-class}(F_{\text{base}}) = \text{e-class}(F_{\text{head}})$), the diff is marked `PROVEN_EQUIVALENT` in $< 1\text{ ms}$.
* **Global Relational Rules:**
  * **Unsafe Deletion (`cap003a`):** Flags any symbol removed in $F_{\text{head}}$ that remains reachable from live entrypoints, `__all__` exports, or cross-language bridges.
  * **Concurrency & Lock-Order Invariants (`cap008`):** Flags shared state mutations reachable from `async` or multi-threaded entrypoints that lack a common dominating lock acquisition along all `CFG` paths, or that acquire locks $(L_1, L_2)$ in inverted order across two call paths.

#### Stage 2: Z3 SMT Counterexample Prover (`z3_prover.py`)
When `egglog` cannot prove equivalence and a structural anomaly is present (`call_swap`, `return_swap`, `guard_inversion`, `shadow_assign`, or an intent post-condition $\Phi_{\text{intent}}$), `z3_prover.py` translates the diverging $\text{U-SSA}$ slice into **Z3** (`QF_BV` / `QF_LIA` / `QF_UF` theories):
* **Call & Return Swap Proof (`cap004`):** Models functions as uninterpreted functions $g(a, b)$ with distinct parameter sorts/tags and solves:
  $$\exists \vec{x} : F_{\text{base}}(\vec{x}) \neq F_{\text{head}}(\vec{x})$$
* **Guard Inversion Proof:** Solves for a concrete input vector $\vec{x}^*$ where the branch condition evaluates to `True` in $F_{\text{base}}$ and `False` in $F_{\text{head}}$, leading to divergent return or exception states.
* **Witness Extraction:** When Z3 returns `SAT`, `solver.model()` is serialized into an immutable `CounterexampleWitness` containing the exact input variable values that trigger the failure.

#### Stage 3: Taint-Tracked Secret & Liveness Engine (`secrets_taint.py`)
Upgrades `verifyci/secrets/` (`cap002b`, `cap011`):
1. **Multi-Pass Decoding + Shannon Entropy:** Preserves recursive Base64/Hex/URL decoding (`decoder.py`) and entropy prefiltering (`entropy.py`).
2. **DFG Taint-to-Sink Tracking:** Traces candidate secret variables along `DFG_EDGE` chains into logging (`logger.*`, `print`), network (`requests.*`, `httpx.*`), or serialization sinks.
3. **Conformal Mock/Fixture Triage:** Distinguishes unit-test mocks from production credentials using structural file-partition context (`partition.py`) plus the calibrated System 1 Judge.

---

### 3.6 Layer 6: Vendor-Neutral BYO-AI & Conformal Layer (`verifyci_v2/neural/`)

#### A. Four Pluggable Provider Adapters (`adapters.py`)
All AI interactions flow through three strict protocols (`EmbeddingProviderProtocol`, `DiscriminativeJudgeProtocol`, `GenerativeSynthesizerProtocol`) backed by four zero-lock-in adapters:
1. `deterministic` (Default — zero AI weights, uses AST/DFG heuristics + BM25).
2. `local-onnx` (CPU-only quantized ONNX models for reranking and NLI classification).
3. `ollama` (Local open-weights models via `http://localhost:11434`).
4. `openai-compatible` (Any user API key for OpenRouter, vLLM, llama.cpp, OpenAI, Anthropic, or Gemini via pure `httpx`).

#### B. `llguidance` Grammar Masking (`grammar_mask.py`)
For local models, `llguidance` enforces context-free grammars over token logits in $\sim 50\text{ }\mu\text{s/token}$, guaranteeing 100% schema-valid `BooleanJudgment`, `CategoricalChoice`, and `OrdinalScore` outputs with zero retry loops.

#### C. Split Conformal Prediction Gate (`conformal.py`)
Because different user-supplied LLMs have wildly different probability calibration, `vc2 calibrate` computes the empirical non-conformity quantile $\hat{q}_{1-\alpha}$ on VerifyCI's held-out benchmark corpora (`cap002_heldout`, `cap011`) for a target false-pass rate $\alpha$ (default $\alpha = 0.02$):
$$\hat{q}_{1-\alpha} = \text{Quantile}\left(\{1 - \hat{p}_M(y_i \mid x_i)\}_{i=1}^n \cup \{\infty\},\; \frac{\lceil (n + 1)(1 - \alpha) \rceil}{n}\right)$$
At CI runtime, if the prediction set $\mathcal{C}(x_{\text{new}}) = \{y : 1 - \hat{p}_M(y \mid x_{\text{new}}) \le \hat{q}_{1-\alpha}\}$ has size $|\mathcal{C}(x_{\text{new}})| \neq 1$ or contains any defect label, VerifyCI **abstains** from the neural shortcut and escalates the diff to `egglog` + Z3.

#### D. Z3-Verified CEGIS Auto-Repair (`cegis_repair.py`)
When `vc2 fix` is invoked on a proven defect:
1. The failing function slice and Z3 `CounterexampleWitness` are scrubbed by `secrets/redaction.py`.
2. `GenerativeSynthesizerProtocol` proposes a minimal unified diff patch (up to $N = 3$ rounds).
3. Each candidate patch is parsed in-memory, lowered to $\text{U-SSA}$, and checked by `egglog` + `z3_prover.py`.
4. A patch is emitted into the SARIF v2.1.0 `fixes` array **if and only if** Z3 returns `UNSAT` (the counterexample is eliminated) and zero new unresolved references are introduced.

---

### 3.7 Layer 7: Wasmtime Sandbox & Cryptographic Provenance (`sandbox/` & `provenance/`)

* **WebAssembly Checker Sandbox (`wasm_runner.py`):** Custom repository checkers compile to WebAssembly components executed via `wasmtime`. Each plugin receives a read-only view of the $\text{U-SSA}$ graph, zero host filesystem/network capabilities, and a deterministic CPU instruction fuel limit.
* **`in-toto` v1.0 DSSE & `gittuf` RSL (`dsse_intoto.py`, `gittuf_rsl.py`):**
  * Every verification run emits an RFC 8785 canonical `in-toto` v1.0 attestation containing the base/head commit SHAs, $\text{U-SSA}$ Merkle root, Z3 proof summary, and BYO-AI `ConformalProfile` digest.
  * The attestation is signed via Ed25519 or keyless Sigstore OIDC and appended to the repository's **`gittuf` Reference State Log (`refs/gittuf/reference-state-log`)** and `refs/notes/verifyci`, preventing silent branch/tag tampering or replay attacks across stateless CI runners.

---

## 4. Canonical Data Contracts (`verifyci_v2/contracts/`)

```python
from __future__ import annotations
from typing import Literal
import msgspec


class USSABasicBlock(msgspec.Struct, frozen=True, kw_only=True):
    block_id: str
    instructions: tuple[str, ...]
    phi_nodes: tuple[str, ...]
    terminator_condition: str | None = None


class CounterexampleWitness(msgspec.Struct, frozen=True, kw_only=True):
    checker_id: str
    smt_status: Literal["SAT", "UNSAT", "UNKNOWN"]
    input_assignments: dict[str, str | int | float | bool | None]
    base_return_state: str
    head_return_state: str
    proof_time_ms: float


class CandidateFix(msgspec.Struct, frozen=True, kw_only=True):
    file_path: str
    start_line: int
    end_line: int
    replacement_text: str
    unified_diff: str
    z3_verified_unsat: bool


class VerificationFinding(msgspec.Struct, frozen=True, kw_only=True):
    finding_id: str
    rule_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    verdict: Literal["PASS", "WARN", "FAIL", "PROVEN_EQUIVALENT", "UNGROUNDED"]
    file_path: str
    start_line: int
    end_line: int
    message: str
    witness: CounterexampleWitness | None = None
    fixes: tuple[CandidateFix, ...] = ()


class InTotoVerificationPredicate(msgspec.Struct, frozen=True, kw_only=True):
    schema_version: Literal["verifyci.v2.0"] = "verifyci.v2.0"
    repo_id: str
    base_commit_sha: str
    head_commit_sha: str
    ussa_merkle_root: str
    gittuf_rsl_entry_hash: str
    ai_provider: str
    conformal_profile_hash: str | None
    findings: tuple[VerificationFinding, ...]
```

---

## 5. Failure Modes, Security Boundaries & Resource Budgets

| Failure / Attack Vector | Architectural Mitigation in VerifyCI v2.0 |
| :--- | :--- |
| **Z3 Path Explosion / Nonlinear Arithmetic Timeout** | Strict per-function solver timeout (`smt_timeout_ms = 2000`) and memory cap (`256 MB`). If Z3 returns `UNKNOWN`, VerifyCI falls back to the `egglog` structural Datalog rule and marks the finding with `smt_status = "UNKNOWN"` (never silently passing a flagged structural defect). |
| **Adversarial Prompt Injection in Code Comments** | Code comments and docstrings are stripped from the $\text{U-SSA}$ representation before symbolic checking. Even if a comment tricks the BYO-AI System 1 Judge, any `FAIL` or `PASS` override is gated by the conformal threshold $\hat{q}_{1-\alpha}$ and verified by deterministic `egglog`/Z3 rules. |
| **Secret Leakage to Remote BYO-AI Endpoints** | All code slices and diffs pass through `secrets/redaction.py` (replacing high-entropy strings and matched credential patterns with `<REDACTED_SECRET_1>`) prior to constructing any `httpx` request to a remote LLM. |
| **Malicious Third-Party Checker Plugin** | Custom checkers execute inside `wasmtime` with `wasi_nn` / filesystem / socket capabilities disabled and a hard deterministic CPU fuel limit (`10,000,000` instructions per check). |
| **Compromised CI Runner / Force-Push Replay** | `gittuf_rsl.py` verifies the hash-chained Reference State Log (`refs/gittuf/reference-state-log`) before accepting historical receipts, detecting any rolled-back ref or forged git note. |

---

## 6. v1.x $\rightarrow$ v2.0 Subsystem Migration Matrix

| v1.x Module Path | v2.0 Target Module Path | Migration Action |
| :--- | :--- | :--- |
| `verifyci/contracts/*` | `verifyci_v2/contracts/*` | Upgrade frozen dataclasses to `msgspec.Struct` + RFC 8785 JCS + `BLAKE3`. |
| `verifyci/ingestion/extractor.py`, `parser.py` | `verifyci_v2/ingestion/stack_graphs.py`, `ssa_lower.py` | Replace single-pass AST walk with `tree-sitter-stack-graphs` + $\text{U-SSA}$ compiler. |
| `verifyci/ingestion/incremental.py` | `verifyci_v2/ingestion/salsa_cutoff.py` | Upgrade file-level cache to function-level $H_{\text{interface}}$ vs. $H_{\text{body}}$ early cutoff. |
| `verifyci/storage/graph_store.py`, `graph_cache.py` | `verifyci_v2/store/duckdb_cpg.py` | Consolidate SQLite + JSON caches into Arrow-native DuckDB CPG tables. |
| `verifyci/retrieval/dense.py`, `sparse.py`, `reranker.py` | `verifyci_v2/store/model2vec_embed.py`, `rabitq_index.py` | Replace heavy float caches with `Model2Vec` + $1\text{-bit}$ `RaBitQ` error-bounded pruning. |
| `verifyci/verification/call_swap.py`, `return_swap.py`, `guard_inversion.py`, `shadow_assign.py` | `verifyci_v2/symbolic/egglog_engine.py`, `z3_prover.py` | Replace heuristic AST pattern rules with `egglog` equality saturation + Z3 SMT counterexample proofs. |
| `verifyci/verification/deletion.py`, `removal.py` | `verifyci_v2/symbolic/egglog_engine.py` | Express as declarative Datalog reachability rules over the full polyglot CPG. |
| `verifyci/secrets/*` | `verifyci_v2/symbolic/secrets_taint.py` | Add $\text{DFG}$ source-to-sink taint tracking + conformal mock triage on top of v1 entropy/decoder passes. |
| `verifyci/interface/mcp_server.py`, `fastmcp_server.py` | `verifyci_v2/interface/fastmcp_daemon.py` | Unify into a single stateful FastMCP daemon with `watchfiles` hot-reloading. |
| `verifyci/memory/ledger.py`, `verification/receipts.py` | `verifyci_v2/provenance/dsse_intoto.py`, `gittuf_rsl.py` | Upgrade local SQLite hash ledger to `in-toto` v1.0 DSSE envelopes + `gittuf` RSL git anchoring. |