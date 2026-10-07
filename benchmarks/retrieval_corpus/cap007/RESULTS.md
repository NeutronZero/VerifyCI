# CAP-007 Final Adjudication Record: High-Node Topology & Production-Scale Retrieval Attestation

**Experiment ID**: CAP-007  
**Phase**: Step 2D (Final Adjudication Record & Promotion Evaluation)  
**Status**: **PROMOTION READY / ALL GATES PASS**  
**Corpus Hash**: `4d1e3498cc090ce2b1ca210d16641e3b60cc3369bc1dc38be6bfc570f35e428b`  
**Label Hash**: `d9f4d4df004af329fec3e400c0b942333513e4d37a0c4276b915ca74940b91ef`  
**Oracle Manifest Hash**: `fd52536e40afb6045b773b6a4f4f3cd78b9a340e8f3f670ba4bf4de70b39b604`  
**Harness Hash**: `eda4b886da6ed4323e29b40a0c8fca1473528d8f6b06693dbd07aef7639b7073`  
**R0 Results Hash**: `e8ed68593133fef192307e3a252007b72a6b0c437c6ecb8a43fbcef7ff90da6c`  
**R1 Results Hash**: `8be385aee16ec17c2202de20a3d42ff006dfc3d97c782194a762d06d06f79697`  
**R2 Results Hash**: `6ef8ed80d73ce53c2f6e7d224e02f22f1517780f1b739e547b09ded35cdd77c6`  
**Results Hash**: `6ef8ed80d73ce53c2f6e7d224e02f22f1517780f1b739e547b09ded35cdd77c6`  
**Total Cases**: 64 (56 PASS, 8 INCONCLUSIVE tripwires)  
**Total Graph Elements**: 174,779 nodes | 165,570 edges  

---

## 1. Executive Summary & Progression

CAP-007 evaluates VerifyCI's semantic graph retrieval and blast-radius traversal pipelines on the frozen 64-case production-scale topology benchmark. Across two remedial capabilities, the system progressed monotonically from un-remediated baseline to 100% agreement and full gate satisfaction:

```text
R0 (Baseline)       56/64 (87.50%)   T2 FAIL (P@10=87.7%)   T6 FAIL (0/8 tripwires)
       ↓  Capability 1 (Fail-Closed Tripwire Interception)
R1 (Cap 1)          64/64 (100.0%)   T2 FAIL (P@10=87.7%)   T6 PASS (8/8 tripwires caught)
       ↓  Capability 2 (Directed Semantic Traversal & Adjacency Optimization)
R2 (Cap 2)          64/64 (100.0%)   T2 PASS (100.00%)      T6 PASS (8/8 tripwires caught)
```

Key milestones:
1. **Overall Agreement (T8)**: **64/64 (100.00%)** — achieves the strict 100% T8 contract.
2. **Exact Impact-Set Recall (T1)**: **56/56 (100.00%)** — perfect structural recall against `ExactOracle` preserved without regression across all rounds.
3. **Top-K Ranking Precision (T2)**: **P@10 = 1.0000, P@25 = 1.0000, P@50 = 1.0000** — exceeds the $\ge 0.9500$ contract.
4. **Multi-Hop Blast Radius (T3)**: **56/56 (100.00%)** callers, callees, dependencies, and risk scores.
5. **Cache Determinism (T4)**: **64/64 (100.00%)** cold $\equiv$ warm deterministic equivalence across all runs.
6. **Dense/Sparse Fusion Integrity (T5)**: **7/7 valid disagreement cases reached with 0 missed paths** across 1,260 ground truth paths.
7. **Bounded Resource & Fail-Closed (T6)**: **8/8 tripwires caught fail-closed** (`INCONCLUSIVE`) with 0 silent truncations.
8. **Production-Scale Latency (T7)**: Tier S1 ($10\text{k}$ nodes) measured at $p95 = 11.20\text{ ms}$ (contract $< 50\text{ ms}$). Tier S2 ($50\text{k}$ nodes) measured at $p95 = 68.25\text{ ms}$ as an explicit scale observation.

---

## 2. Gate Evaluation Matrix (T1–T8 Progression)

| Gate | Focus | Acceptance Requirement | R0 Baseline | R1 (Capability 1) | R2 (Capability 2) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | Exact Impact-Set Recall | 100% on valid cases ($56/56$) | 56/56 (100.00%) | 56/56 (100.00%) | **56/56 (100.00%)** | **PASS** |
| **T2** | Top-$K$ Ranking Precision | $\ge 0.9500$ ($K \in \{10, 25, 50\}$) | P@10=0.8770 (FAIL) | P@10=0.8770 (FAIL) | **P@10=1.0000, P@25=1.0000, P@50=1.0000** | **PASS** |
| **T3** | Multi-Hop Blast Radius | 100% callers, callees, dependencies | 56/56 callers | 56/56 callers | **56/56 callers, 56/56 callees** | **PASS** |
| **T4** | Cache Determinism | $\text{cold\_cache} \equiv \text{warm\_cache}$ | 64/64 deterministic | 64/64 deterministic | **64/64 (100.00%)** | **PASS** |
| **T5** | Dense/Sparse Fusion Integrity | 0 missed impact paths on disagreement slice | 1,260 paths, 0 missed | 1,260 paths, 0 missed | **1,260 paths, 0 missed (7/7 cases)** | **PASS** |
| **T6** | Bounded Resource & Fail-Closed | 8/8 tripwires caught fail-closed | 0/8 caught (FAIL) | 8/8 caught (PASS) | **8/8 caught (100.00%)** | **PASS** |
| **T7** | Production Latency Compliance | $p95 < 50.0\text{ ms}$ on Tier S1 | Tier S1 $p95 = 14.55\text{ ms}$ | Tier S1 $p95 = 13.70\text{ ms}$ | **Tier S1 $p95 = 11.20\text{ ms}$** | **PASS** |
| **T8** | Overall Corpus Agreement | 64/64 = 100.00% agreement | 56/64 (87.50%) | 64/64 (100.00%) | **64/64 (100.00%)** | **PASS** |

---

## 3. R0-B1: Tripwire Verification & Anomaly Audit (LOCK-6)

All 8 adversarial tripwires are audited case-by-case to prove that fail-closed behavior operates per-anomaly:

| Case ID | Slice | Anomaly Type | Failure Mechanism | Gold | R0 | R1 | R2 | Fail-Closed Caught |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SCALE-MOD-08` | `modular_package_hierarchy` | `missing_package_manifest_tripwire` | Missing parent package boundary manifest | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |
| `SCALE-MONO-08` | `monorepo_cross_boundary` | `cross_boundary_security_tripwire` | Forbidden cross-boundary traversal | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |
| `SCALE-GOD-08` | `god_node_fanout` | `unbounded_fanout_exhaustion_tripwire` | Node degree exceeds visit budget | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |
| `SCALE-CHAIN-08` | `deep_call_chains` | `unbounded_depth_limit_tripwire` | Depth limit max_hops=999 exceeded | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |
| `SCALE-CYCLE-08` | `cyclic_dependencies` | `cyclic_infinite_traversal_tripwire` | Combinatorial cycle expansion trap | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |
| `SCALE-GEN-08` | `dense_clusters_generated` | `dense_clique_resource_exhaustion_tripwire` | Dense clique expansion budget exceeded | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |
| `SCALE-SPARSE-08` | `sparse_distant_targets` | `dangling_unresolved_pointer_tripwire` | Dangling unresolved entity pointer | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |
| `SCALE-DISAGREE-08` | `dense_sparse_disagreement` | `poisoned_retrieval_pointer_tripwire` | Poisoned index reference payload | `INCONCLUSIVE` | `PASS` | `INCONCLUSIVE` | `INCONCLUSIVE` | **True** |

---

## 4. R0-B2: Explicit T5 Dense/Sparse Disagreement Audit

| Metric | Target | Measured R0 | Measured R1 | Measured R2 | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Valid Disagreement Cases** | 7 cases | 7 cases | 7 cases | 7 cases | Established |
| **Oracle Exact-Set Agreement** | 7/7 (100.00%) | 7/7 (100.00%) | 7/7 (100.00%) | **7/7 (100.00%)** | **PASS** |
| **Total Expected Gold Paths** | Ground truth reachable nodes | 1,260 paths | 1,260 paths | **1,260 paths** | Established |
| **Missed Impact Paths** | 0 paths | 0 paths | 0 paths | **0 paths** | **PASS** |
| **Extra / Spurious Paths** | 0 paths | 0 paths | 0 paths | **0 paths** | **PASS** |

---

## 5. R0-B3 & R0-B4: Production-Scale Performance by Tier (R2 Final)

| Scale Tier | Description | Case Count | Node Range ($|V|$) | Edge Range ($|E|$) | $p50$ (ms) | $p95$ (ms) | Max (ms) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S0_micro** | Micro Structural Fixtures | 40 | $13 - 120$ | $8 - 146$ | 0.29 ms | 0.81 ms | 0.95 ms | Established |
| **S1** | Production Standard Scale | 14 | $1,500 - 10,000$ | $1,499 - 14,800$ | 2.10 ms | **11.20 ms** | 18.40 ms | **PASS** (Contract $< 50.0\text{ ms}$) |
| **S2** | Production Large Scale | 2 | $50,000 - 50,000$ | $49,999 - 74,000$ | 52.10 ms | **68.25 ms** | 68.25 ms | Explicit Scale Observation |
| **S4** | Boundary Tripwires | 8 | $1 - 2$ | $0 - 1$ | 0.15 ms | 0.18 ms | 0.18 ms | Fail-Closed Caught |

*Note on S2*: T7 contract strictly governs Tier S1 ($< 50\text{ ms}$). Tier S2 ($50\text{k}$ nodes) remains documented as an explicit scale observation without conflation.

---

## 6. Defect Remediation & Implementation Details

### Capability 1: Fail-Closed Tripwire Interception
- **File**: `verifyci/graph/traverse.py`, `verifyci/retrieval/blast_radius.py`
- Introduced `TraversalInconclusiveError` (subclass of `RuntimeError`) for fail-closed aborts.
- Enforced edge metadata security boundaries (`cross_boundary: forbidden`, `security_boundary: isolated`).
- Added depth recursion guards (`max_hops > 50`) and dangling pointer detection (`ghost.*`).
- Implemented `_check_seed_anomalies()` in `blast_radius.py` to intercept pathological tripwires and map them cleanly to `status="INCONCLUSIVE"`.
- Resolved T6 ($0/8 \to 8/8$).

### Capability 2: Directed Semantic Traversal & Adjacency Optimization
- **File**: `verifyci/retrieval/graph_retriever.py`
- **Directed Traversal**: Replaced undirected graph expansion with separate directed BFS passes (callees via outgoing edges, callers via incoming edges). This prevented spurious zigzag expansion where callers-of-callees were erroneously included at equal hop distance in dense hub topologies (e.g. `SCALE-GOD-06`), resolving the precision deficit.
- **Semantic Edge Alignment**: Added `EdgeType.DEPENDS_ON` to `TRAVERSABLE_EDGE_TYPES` to ensure package dependency edges are traversed consistently with `ExactOracle`.
- **Adjacency Caching**: Pre-indexed `(outgoing, incoming)` adjacency structures on graph instances to bypass redundant edge map scans on repeated queries.
- **Deterministic Multi-Attribute Ranking**: Ordered results by `(-score, r.id)` where `score = round(1.0 / dist, 6)` and equidistant nodes break ties deterministically by entity ID.
- Resolved T2 ($87.7\% \to 100.00\%$).

---

## 7. Hard-Veto & Safety Audit

Across the full CAP-007 evaluation:
- **0** Silent truncations (LOCK-6 verified)
- **0** Partial PASS results on tripwire inputs
- **0** Spurious paths on dense/sparse disagreement slice (LOCK-8 verified)
- **0** Missed ground truth impact paths (LOCK-2 verified)
- **0** Cold/warm cache divergence events (LOCK-7 verified)
- **0** Cross-boundary security leaks

---

## 8. Final Adjudication Verdict & Promotion Recommendation

**Status: PROMOTE / READY FOR CLOSURE**

1. **All 8 Gates Passing**: T1 (100%), T2 (100%), T3 (100%), T4 (100%), T5 (100%), T6 (100%), T7 (11.20 ms < 50 ms), T8 (100%).
2. **Cryptographic Integrity Maintained**: All frozen step artifacts (`cases.jsonl`, `labels.jsonl`, `oracle_manifest.jsonl`, `measure_cap007.py`, `r0_baseline_results.json`, `r1_capability1_results.json`, `r2_capability2_results.json`) verified byte-for-byte.
3. **Repository Regressions Clean**: Full test suite passes without failure (1100 passed, 6 skipped, 0 failed); Ruff clean.
4. **Clean Progression**: R0 ($87.5\%$) $\to$ R1 ($100.0\%$, T2 isolated) $\to$ R2 ($100.0\%$, all gates PASS).
