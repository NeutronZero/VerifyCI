# CAP-007 R0 Baseline: High-Node Topology & Production-Scale Retrieval Attestation

**Experiment ID**: CAP-007  
**Phase**: Step 2A (R0 Baseline on Un-Remediated VerifyCI)  
**Status**: **MEASURED / NOT PROMOTABLE**  
**Corpus Hash**: `4d1e3498cc090ce2b1ca210d16641e3b60cc3369bc1dc38be6bfc570f35e428b`  
**Label Hash**: `d9f4d4df004af329fec3e400c0b942333513e4d37a0c4276b915ca74940b91ef`  
**Oracle Manifest Hash**: `fd52536e40afb6045b773b6a4f4f3cd78b9a340e8f3f670ba4bf4de70b39b604`  
**Harness Hash**: `836dcc3617e0550ed1be95771461dce3fbd65ef4424939563bb3db9d894747a9`  
**Results Hash**: `e8ed68593133fef192307e3a252007b72a6b0c437c6ecb8a43fbcef7ff90da6c`  
**Total Cases**: 64 (56 PASS, 8 INCONCLUSIVE tripwires)  
**Total Graph Elements**: 174,779 nodes | 165,570 edges  

---

## 1. Executive Summary

The R0 baseline evaluates VerifyCI's un-remediated graph retrieval and blast-radius traversal pipelines on the frozen 64-case production-scale CAP-007 benchmark.

Key findings:
1. **Overall Agreement**: **56/64 (87.50%)** — fails the strict 100% T8 contract.
2. **Exact Impact-Set Recall (T1)**: **56/56 (100.00%)** — perfect structural recall against `ExactOracle` on all valid queries.
3. **Top-K Ranking Precision (T2)**: **P@10 = 0.8770, P@25 = 0.8647, P@50 = 0.8630** — fails the $\ge 95\%$ contract due to distance-only tie-breaking.
4. **Multi-Hop Blast Radius (T3)**: **56/56 (100.00%)** agreement on callers, callees, dependencies, and risk scores.
5. **Cache Determinism (T4)**: **64/64 (100.00%)** cold $\equiv$ warm deterministic equivalence.
6. **Dense/Sparse Fusion Integrity (T5)**: **7/7 valid disagreement cases reached with 0 missed impact paths** across 1,260 ground truth paths.
7. **Bounded Resource & Fail-Closed (T6)**: **0/8 tripwires caught** — un-remediated VerifyCI silently emits `PASS` instead of failing closed with `INCONCLUSIVE`.
8. **Production-Scale Latency (T7)**: Tier S1 ($10\text{k}$ nodes) measured at $p95 = 14.5\text{ ms}$; Tier S2 ($50\text{k}$ nodes) measured at $p95 = 68.5\text{ ms}$ (un-indexed edge scan bottleneck exposed).

---

## 2. Gate Evaluation Matrix (T1–T8)

| Gate | Focus | Acceptance Requirement | R0 Baseline | Status |
| :--- | :--- | :--- | :--- | :--- |
| **T1** | Exact Impact-Set Recall | 100% on valid cases ($56/56$) | **100.00%** (56/56 exact matches) | **PASS** |
| **T2** | Top-$K$ Ranking Precision | $\ge 0.9500$ ($K \in \{10, 25, 50\}$) | **P@10=0.8770, P@25=0.8647, P@50=0.8630** | **FAIL** |
| **T3** | Multi-Hop Blast Radius | 100% callers, callees, dependencies | **100.00%** (56/56 callers, 56/56 callees) | **PASS** |
| **T4** | Cache Determinism | $\text{cold\_cache} \equiv \text{warm\_cache}$ | **100.00%** (64/64 queries deterministic) | **PASS** |
| **T5** | Dense/Sparse Fusion Integrity | 0 missed impact paths on disagreement slice | **7/7 exact matches, 0 missed paths (1260 paths)** | **PASS** |
| **T6** | Bounded Resource & Fail-Closed | 8/8 tripwires caught fail-closed | **0/8 caught** (silent passes) | **FAIL** |
| **T7** | Production Latency Compliance | $p95 < 50.0\text{ ms}$ on Tier S1 | **Tier S1 $p95 = 14.5\text{ ms}$** (Tier S2 $p95 = 68.5\text{ ms}$) | **PASS** |
| **T8** | Overall Corpus Agreement | 64/64 = 100.00% agreement | **56/64 (87.50%)** | **FAIL** |

---

## 3. R0-B1: Tripwire Verification & Anomaly Audit (LOCK-6)

| Case ID | Slice | Anomaly Type | Failure Mechanism | Gold | Predicted | Fail-Closed Caught |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `SCALE-MOD-08` | `modular_package_hierarchy` | `missing_package_manifest_tripwire` | Missing parent package boundary manifest | `INCONCLUSIVE` | `PASS` | **False** |
| `SCALE-MONO-08` | `monorepo_cross_boundary` | `cross_boundary_security_tripwire` | Forbidden cross-boundary traversal | `INCONCLUSIVE` | `PASS` | **False** |
| `SCALE-GOD-08` | `god_node_fanout` | `unbounded_fanout_exhaustion_tripwire` | Node degree exceeds visit budget | `INCONCLUSIVE` | `PASS` | **False** |
| `SCALE-CHAIN-08` | `deep_call_chains` | `unbounded_depth_limit_tripwire` | Depth limit max_hops=999 exceeded | `INCONCLUSIVE` | `PASS` | **False** |
| `SCALE-CYCLE-08` | `cyclic_dependencies` | `cyclic_infinite_traversal_tripwire` | Combinatorial cycle expansion trap | `INCONCLUSIVE` | `PASS` | **False** |
| `SCALE-GEN-08` | `dense_clusters_generated` | `dense_clique_resource_exhaustion_tripwire` | Dense clique expansion budget exceeded | `INCONCLUSIVE` | `PASS` | **False** |
| `SCALE-SPARSE-08` | `sparse_distant_targets` | `dangling_unresolved_pointer_tripwire` | Dangling unresolved entity pointer | `INCONCLUSIVE` | `PASS` | **False** |
| `SCALE-DISAGREE-08` | `dense_sparse_disagreement` | `poisoned_retrieval_pointer_tripwire` | Poisoned index reference payload | `INCONCLUSIVE` | `PASS` | **False** |

---

## 4. R0-B2: Explicit T5 Dense/Sparse Disagreement Audit

| Metric | Target | Measured R0 | Status |
| :--- | :--- | :--- | :--- |
| **Valid Disagreement Cases** | 7 cases | 7 cases | Established |
| **Oracle Exact-Set Agreement** | 7/7 (100.00%) | **7/7 (100.00%)** | **PASS** |
| **Total Expected Gold Paths** | Ground truth reachable nodes | **1,260 paths** | Established |
| **Missed Impact Paths** | 0 paths | **0 paths** | **PASS** |
| **Extra / Spurious Paths** | 0 paths | **0 paths** | **PASS** |

---

## 5. R0-B3 & R0-B4: Production-Scale Performance by Tier

| Scale Tier | Description | Case Count | Node Range ($|V|$) | Edge Range ($|E|$) | $p50$ (ms) | $p95$ (ms) | Max (ms) | Peak RSS |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S0_micro** | Micro Structural Fixtures | 40 | $13 - 120$ | $8 - 146$ | 0.35 ms | 0.92 ms | 1.07 ms | 12.2 KB |
| **S1** | Production Standard Scale | 14 | $1,500 - 10,000$ | $1,499 - 14,800$ | 2.52 ms | 14.55 ms | 21.46 ms | 470.7 KB |
| **S2** | Production Large Scale | 2 | $50,000 - 50,000$ | $49,999 - 74,000$ | 58.53 ms | 68.46 ms | 68.46 ms | 3,840.6 KB |
| **S4** | Boundary Tripwires | 8 | $1 - 2$ | $0 - 1$ | 0.16 ms | 0.20 ms | 0.20 ms | 2.1 KB |

---

## 6. Defect Isolation & Capability Sequencing

The R0 baseline isolates two independent defect classes:

1. **Capability 1 (Fail-Closed Tripwire Interception in `blast_radius.py`)**:
   - Address the 8 tripwire anomalies (budget exhaustion, depth limits, missing manifests, dangling pointers) by evaluating to `INCONCLUSIVE` rather than silent `PASS`.
   - Resolves T6 ($0/8 \to 8/8$) and advances overall agreement ($56/64 \to 64/64$).

2. **Capability 2 (Top-K Ranking Multi-Attribute Tie-Breaking in `graph_retriever.py`)**:
   - Refine degree centrality tie-breaking to achieve $\ge 95\%$ Top-K precision on dense cluster graphs.
   - Resolves T2 ($87.7\% \to \ge 95\%$).
