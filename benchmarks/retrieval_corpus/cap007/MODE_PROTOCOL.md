# CAP-007: High-Node Topology & Production-Scale Retrieval Attestation Protocol

**Experiment ID**: CAP-007  
**Corpus SHA-256**: `4d1e3498cc090ce2b1ca210d16641e3b60cc3369bc1dc38be6bfc570f35e428b`  
**Label SHA-256**: `d9f4d4df004af329fec3e400c0b942333513e4d37a0c4276b915ca74940b91ef`  
**Oracle Manifest SHA-256**: `fd52536e40afb6045b773b6a4f4f3cd78b9a340e8f3f670ba4bf4de70b39b604`  
**Harness SHA-256**: `836dcc3617e0550ed1be95771461dce3fbd65ef4424939563bb3db9d894747a9`  
**R0 Results SHA-256**: `e8ed68593133fef192307e3a252007b72a6b0c437c6ecb8a43fbcef7ff90da6c`  
**Total Cases**: 64 (56 PASS, 8 INCONCLUSIVE tripwires)  
**Total Nodes**: 174,779 | **Total Edges**: 165,570  

## 1. Objective & Headline Invariants

Gate **CAP-007** establishes that VerifyCI's semantic graph retrieval and topology analysis remain correct, deterministic, and resource-bounded on large semantic graphs while meeting defined latency and recall contracts under adversarial graph structure and concurrent query load.

### Core Correctness Invariant
$$\text{ExactImpactOracle}(G, q, \text{max\_hops}) \equiv \text{VerifyCIImpact}(G, q, \text{max\_hops})$$

### Cache Determinism Invariant
$$\text{VerifyCIImpact}(\text{cold\_cache}) \equiv \text{VerifyCIImpact}(\text{warm\_cache})$$

### Fail-Closed Safety Invariant (No Silent Truncation)
$$\text{TraversedNodes}(q) < \text{RequiredNodes}(q) \implies \text{Status} = \text{INCONCLUSIVE} \; (\text{NEVER a partial PASS})$$

---

## 2. The Ten Protocol Locks

### LOCK-1: Exact Retrieval Oracle
Every benchmark query has a ground-truth impact set established by an **independent exact traversal oracle** (`oracle.py`). The oracle has **zero imports** from `verifyci` (no dense, sparse, fusion, cache, or blast radius modules).

### LOCK-2: Separate Correctness from Ranking
Correctness is measured independently from ranking:
- **Exact Impact-Set Recall**: 100% completeness of reachable semantic dependencies, independent of $K$.
- **Ranked Retrieval**: Evaluated separately at fixed $K \in \{10, 25, 50\}$ for `Recall@K`, `Precision@K`, `MRR`, and `NDCG`.
A high ranking score cannot compensate for an omitted dependency.

### LOCK-3: No Synthetic-Only Success
Graphs represent realistic large software topologies, not merely duplicated dummy nodes. Topologies include modular trees, multi-project monorepos, high-fanout hubs, deep call chains, cycles, and generated code regions.

### LOCK-4: Scale Tiers Frozen Prior to Optimization
Scale tiers are grounded in the host hardware profile (8 CPUs, 7.73 GB RAM) and frozen before any code modifications:
- **Tier S1**: $10\text{k} - 25\text{k}$ nodes ($p95 < 10\text{ ms}$)
- **Tier S2**: $50\text{k} - 100\text{k}$ nodes ($p95 < 50\text{ ms}$)
- **Tier S3**: $100\text{k} - 250\text{k}$ nodes ($p95 < 100\text{ ms}$)
- **Tier S4**: $250\text{k} - 500\text{k}$ nodes (Stress tier: bounded resource, fail-closed)

### LOCK-5: Performance Distribution, Not Single-Run Latency
Latency compliance is evaluated across full distributions ($p50$, $p95$, $p99$, $\text{max}$, timeout rate) with explicit hardware attribution, separating algorithmic correctness from host variance.

### LOCK-6: No Silent Truncation (Fail-Closed)
Resource exhaustion or timeout must yield a bounded `INCONCLUSIVE` verdict. Silently truncating graph traversal or dropping unreachable paths while reporting `PASS` is a hard veto violation.

### LOCK-7: Cache Correctness
For any query $q$, the canonical semantic impact set produced under a cold cache must be identical to that produced under a warm cache: $\text{Result}(\text{cold}) \equiv \text{Result}(\text{warm})$.

### LOCK-8: Dense/Sparse Independence
The oracle operates strictly on graph structure. Ground-truth traversal is completely independent of lexical embedding or token inverted index representations.

### LOCK-9: Adversarial Topology First-Class
Adversarial structures are first-class slices: god-node fanout, circular dependencies, deep call chains, large generated files, hub-and-spoke graphs, long sparse paths, dense local clusters, and dense/sparse keyword disagreement.

### LOCK-10: No Benchmark-Driven Mutation
Corpus cases, oracle traversal rules, query parameters, and labels are cryptographically frozen prior to R0 baseline measurement. Never modify the benchmark in response to implementation failures.

---

## 3. Independent Graph Schema Specification

The benchmark graphs are declared in a clean-room specification completely decoupled from internal database representations:

- **Entity / Node**:
  - `id`: Unique string identifier (e.g., `pkg_a.mod_b.func_c`)
  - `type`: Semantic entity type (`FUNCTION`, `METHOD`, `CLASS`, `VARIABLE`, `MODULE`)
  - `name`: Symbol name
  - `module`: Logical module / file path
- **Edge**:
  - `src`: Source entity ID
  - `dst`: Target entity ID
  - `type`: Relationship type
- **Edge Filtering Rules**:
  - **Traversable Semantic Call Flow**: `{"CALLS", "IMPORTS", "INHERITS", "DEPENDS_ON"}`
  - **Non-Traversable Structural**: `{"CONTAINS", "DOCUMENTS", "DEFINES", "REFERENCES"}`

---

## 4. Gates T1–T8 Acceptance Contracts

| Gate | Focus | Acceptance Requirement |
| :--- | :--- | :--- |
| **T1** | Exact Impact-Set Recall | 100% recall against `ExactOracle` on all valid queries |
| **T2** | Top-$K$ Ranking Precision | $\text{Precision}@K \ge 95\%$ ($K \in \{10, 25, 50\}$) with deterministic tie-breaking |
| **T3** | Multi-Hop Blast Radius Agreement | 100% agreement on affected callers, callees, and dependency impact |
| **T4** | Cache Determinism Attestation | $\text{cold\_cache} \equiv \text{warm\_cache}$ across all queries |
| **T5** | Dense/Sparse Fusion Integrity | 0 missed impact paths when lexical keywords diverge from call graph |
| **T6** | Bounded Resource & No Silent Truncation | 0 silent truncations; partial or timed-out traversals yield `INCONCLUSIVE` |
| **T7** | Production Latency Compliance | $p95 < 50\text{ ms}$ on Production Tiers S1 and S2 |
| **T8** | Overall Corpus Agreement | 64/64 = 100.00% agreement against frozen labels |
