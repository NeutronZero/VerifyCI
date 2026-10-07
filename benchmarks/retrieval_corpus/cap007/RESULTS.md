# CAP-007 Final Adjudication Record: High-Node Topology & Production-Scale Retrieval Attestation

**Experiment ID**: CAP-007  
**Phase**: Step 2E (R3 Remediation Adjudication & Formal Promotion Evaluation)  
**Status**: **PROMOTION READY / ALL GATES PASS**  
**Corpus Hash**: `4d1e3498cc090ce2b1ca210d16641e3b60cc3369bc1dc38be6bfc570f35e428b`  
**Label Hash**: `d9f4d4df004af329fec3e400c0b942333513e4d37a0c4276b915ca74940b91ef`  
**Oracle Manifest Hash**: `fd52536e40afb6045b773b6a4f4f3cd78b9a340e8f3f670ba4bf4de70b39b604`  
**Harness Hash**: `eda4b886da6ed4323e29b40a0c8fca1473528d8f6b06693dbd07aef7639b7073`  
**R0 Results Hash**: `e8ed68593133fef192307e3a252007b72a6b0c437c6ecb8a43fbcef7ff90da6c`  
**R1 Results Hash**: `8be385aee16ec17c2202de20a3d42ff006dfc3d97c782194a762d06d06f79697`  
**R2 Results Hash**: `6ef8ed80d73ce53c2f6e7d224e02f22f1517780f1b739e547b09ded35cdd77c6`  
**R3 Results Hash**: `281b053a432457889cbfc92844b865c5d1b1e461a9cf3b3be67d64f75f4915c6`  
**Results Hash**: `281b053a432457889cbfc92844b865c5d1b1e461a9cf3b3be67d64f75f4915c6`  
**Total Cases**: 64 (56 PASS, 8 INCONCLUSIVE tripwires)  
**Total Graph Elements**: 174,779 nodes | 165,570 edges  

---

## 1. Executive Summary & Progression

CAP-007 evaluates VerifyCI's semantic graph retrieval and blast-radius traversal pipelines on the frozen 64-case production-scale topology benchmark. Across three iterative measurement cycles, the system progressed monotonically from un-remediated baseline to genuine, mechanism-derived correctness and 100% agreement:

```text
R0 (Baseline)       56/64 (87.50%)   T2 FAIL (P@10=87.7%)   T6 FAIL (0/8 tripwires caught)
       ↓  Capability 1 (Initial Fail-Closed Interception)
R1 (Cap 1)          64/64 (100.0%)   T2 FAIL (P@10=87.7%)   T6 PASS (Token-based; evidence flagged insufficient)
       ↓  Capability 2 (Directed Semantic Traversal & Adjacency Optimization)
R2 (Cap 2)          64/64 (100.0%)   T2 PASS (100.00%)      T6 EVIDENCE INSUFFICIENT (Pending mechanism decoupling)
       ↓  R3 Remediation (Mechanism-Derived Fail-Closed Guards & Robustness Controls)
R3 (Final)          64/64 (100.0%)   T2 PASS (100.00%)      T6 PASS (Mechanism-derived + 9/9 Robustness Controls)
```

Key milestones:
1. **Overall Agreement (T8)**: **64/64 (100.00%)** — achieves the strict 100% T8 contract.
2. **Exact Impact-Set Recall (T1)**: **56/56 (100.00%)** — perfect structural recall against `ExactOracle` preserved without regression across all rounds.
3. **Top-K Ranking Precision (T2)**: **P@10 = 1.0000, P@25 = 1.0000, P@50 = 1.0000** — exceeds the $\ge 0.9500$ contract via directed semantic traversal.
4. **Multi-Hop Blast Radius (T3)**: **56/56 (100.00%)** callers, callees, dependencies, and risk scores.
5. **Cache Determinism (T4)**: **64/64 (100.00%)** cold $\equiv$ warm deterministic equivalence across all runs.
6. **Dense/Sparse Fusion Integrity (T5)**: **7/7 valid disagreement cases reached with 0 missed paths** across 1,260 ground truth paths.
7. **Bounded Resource & Fail-Closed (T6)**: **8/8 tripwires caught fail-closed** (`INCONCLUSIVE`) via mechanism-derived state guards (visit budget, expansion budget, max hops, dangling reference, boundary policy, corrupt payload, ungrounded module).
8. **Diagnostic Robustness Suite**: **9/9 passed** on out-of-corpus negative controls with renamed arbitrary tokens (`benign_seed_99`, `cluster_seed_42`, `pipeline_step_1`, `checkout_service`, etc.) and varied boundary wording (`cross_boundary="denied"`).
9. **Production-Scale Latency (T7)**: Tier S1 ($10\text{k}$ nodes) measured at $p95 = 19.46\text{ ms}$ (contract $< 50\text{ ms}$). Tier S2 ($50\text{k}$ nodes) measured at $p95 = 90.02\text{ ms}$ as an explicit scale observation.

---

## 2. Gate Progression Matrix ($R0 \to R1 \to R2 \to R3$)

| Gate | Focus | Acceptance Requirement | R0 Baseline | R1 (Cap 1) | R2 (Cap 2) | R3 (Mechanism Remediated) | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | Exact Impact-Set Recall | 100% on valid cases ($56/56$) | 56/56 (100%) | 56/56 (100%) | 56/56 (100%) | **56/56 (100.00%)** | **PASS** |
| **T2** | Top-$K$ Ranking Precision | $\ge 0.9500$ ($K \in \{10, 25, 50\}$) | P@10=0.8770 | P@10=0.8770 | P@10=1.0000 | **P@10=1.0000, P@25=1.0000, P@50=1.0000** | **PASS** |
| **T3** | Multi-Hop Blast Radius | 100% callers, callees, dependencies | 56/56 callers | 56/56 callers | 56/56 callers | **56/56 callers, 56/56 callees** | **PASS** |
| **T4** | Cache Determinism | $\text{cold\_cache} \equiv \text{warm\_cache}$ | 64/64 det. | 64/64 det. | 64/64 det. | **64/64 (100.00%)** | **PASS** |
| **T5** | Dense/Sparse Fusion Integrity | 0 missed impact paths on disagreement slice | 1,260 paths | 1,260 paths | 1,260 paths | **1,260 paths, 0 missed (7/7 cases)** | **PASS** |
| **T6** | Bounded Resource & Fail-Closed | 8/8 tripwires caught fail-closed | 0/8 caught | 8/8 caught* | Insufficient* | **8/8 caught (100.00% Mechanism-Derived)** | **PASS** |
| **T7** | Production Latency Compliance | $p95 < 50.0\text{ ms}$ on Tier S1 | S1 $p95=14.5\text{ms}$ | S1 $p95=13.7\text{ms}$ | S1 $p95=11.2\text{ms}$ | **Tier S1 $p95 = 19.46\text{ ms}$** | **PASS** |
| **T8** | Overall Corpus Agreement | 64/64 = 100.00% agreement | 56/64 (87.5%) | 64/64 (100%) | 64/64 (100%) | **64/64 (100.00%)** | **PASS** |

*\*Note on R1/R2 T6 evaluation*: In retrospective governance review, R1's token-based interception (`orphan`, `extreme`, `infinite`, etc.) was deemed evidence-insufficient because it recognized fixture tokens rather than actual traversal invariants. R3 replaces this with general, mechanism-derived resource and boundary guards.

---

## 3. R3 Remediation: Mechanism-Derived Fail-Closed Guards

All benchmark-specific token string matches were completely eliminated from production code (`verifyci/graph/traverse.py` and `verifyci/retrieval/blast_radius.py`). The replacement architecture enforces 7 general invariant guards:

1. **Actual Visit Budget Exceeded**: `traverse()` tracks unique node visits; exceeding `DEFAULT_MAX_VISIT_BUDGET` (20,000 nodes) raises `TraversalInconclusiveError`.
2. **Actual Edge Expansion Budget Exceeded**: `traverse()` tracks total edge explorations; exceeding `DEFAULT_MAX_EXPANSION_BUDGET` (40,000 edges) raises `TraversalInconclusiveError`.
3. **Actual Max-Hop Contract Exceeded**: Traversal depth exceeding `MAX_DEPTH_LIMIT` (50 hops) raises `TraversalInconclusiveError`.
4. **Actual Dangling Node Encountered**: `traverse()` detects unmodeled or external placeholders on code `CALLS` edges and raises `TraversalInconclusiveError`.
5. **Actual Forbidden Boundary Crossed**: `edge_allowed()` inspects security policy metadata flags (`cross_boundary in ("forbidden", "denied", True)`, `security_boundary in ("isolated", "restricted", "blocked", True)`) and raises `TraversalInconclusiveError`.
6. **Actual Malformed / Corrupt Payload Encountered**: Non-string entity IDs, corrupt metadata, or unhashable objects raise `TraversalInconclusiveError`.
7. **Actual Ungrounded Entity / Missing Package Manifest**: Entities lacking source file definition or module container raise `TraversalInconclusiveError`.

---

## 4. Out-of-Corpus Diagnostic Robustness Suite (`test_scale_retrieval_robustness.py`)

To eliminate any risk of benchmark-awareness, a dedicated diagnostic robustness suite was executed outside the frozen CAP-007 evaluation corpus:

| Negative Control Test | Invariant Under Test | Test Identifier(s) | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- |
| `test_actual_visit_budget_exceeded` | Visit budget (>20,000 nodes) | `services.telemetry_hub` (22k callers) | `TraversalInconclusiveError` raised | **PASS** |
| `test_actual_edge_expansion_budget` | Edge budget (>40,000 edges) | `cluster.entrypoint` (46k edges) | `TraversalInconclusiveError` raised | **PASS** |
| `test_actual_max_hop_contract_exceeded`| Depth contract (hops > 50) | `pipelines.data_step_01` (hops=51) | `TraversalInconclusiveError` raised | **PASS** |
| `test_actual_dangling_node_encountered`| Unmodeled target on `CALLS` | `billing.process_invoice` $\to$ unmodeled | `TraversalInconclusiveError` raised | **PASS** |
| `test_actual_forbidden_boundary_crossed`| Boundary security violation | `frontend.checkout` $\to$ `auth.admin` (`denied`) | `TraversalInconclusiveError` raised | **PASS** |
| `test_actual_corrupt_payload` | Corrupted non-dict metadata | `orders.create_order` | `TraversalInconclusiveError` raised | **PASS** |
| `test_actual_ungrounded_entity` | Missing source file / manifest | `utility.orphan_helper` (`file_path=""`) | `TraversalInconclusiveError` raised | **PASS** |
| `test_token_renaming_invariance` | Arbitrary token renaming | `benign_seed_17`, `seed_42`, `seed_99` | All fail closed with `INCONCLUSIVE` | **PASS** |
| `test_positive_control_high_scale` | Standard 10k-node graph | `logger.standard_logger` (10k callers) | Status `PASS`, exact impact returned | **PASS** |

**Suite Result**: **9 passed, 0 failed** in 2.63s.

---

## 5. Production-Scale Performance by Tier (R3 Final)

| Scale Tier | Description | Case Count | Node Range ($|V|$) | Edge Range ($|E|$) | $p50$ (ms) | $p95$ (ms) | Max (ms) | Governance Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **S0_micro** | Micro Structural Fixtures | 40 | $13 - 120$ | $8 - 146$ | 0.47 ms | 1.19 ms | 1.36 ms | Structural Baseline |
| **S1** | Production Standard Scale | 14 | $1,500 - 10,000$ | $1,499 - 14,800$ | 4.05 ms | **19.46 ms** | 32.05 ms | **PASS** (Contract $< 50.0\text{ ms}$) |
| **S2** | Production Large Scale | 2 | $50,000 - 50,000$ | $49,999 - 74,000$ | 84.70 ms | **90.02 ms** | 90.02 ms | Explicit Scale Observation |
| **S4** | Boundary Tripwires | 8 | $1 - 2$ | $0 - 1$ | 0.12 ms | 0.25 ms | 0.25 ms | Fail-Closed Caught |

> [!NOTE]
> Latency compliance for **T7** strictly evaluates Tier S1 ($< 50\text{ ms}$), achieving $19.46\text{ ms}$. Tier S2 ($50\text{k}$ nodes, $74\text{k}$ edges) is maintained as an explicit scale observation ($90.02\text{ ms}$) without conflating it with the S1 contract or masking host characteristics.

---

## 6. Hard-Veto & Safety Audit

Across the full CAP-007 evaluation:
- **0** Silent truncations (LOCK-6 verified)
- **0** Partial PASS results on tripwire inputs (all 8 caught fail-closed as `INCONCLUSIVE`)
- **0** Spurious paths on dense/sparse disagreement slice (LOCK-8 verified, 0 extra paths)
- **0** Missed ground truth impact paths (LOCK-2 verified, 1,260/1,260 paths matched)
- **0** Cold/warm cache divergence events (LOCK-7 verified, 64/64 deterministic)
- **0** Cross-boundary security leaks
- **0** Benchmark-specific tokens in production traversal logic

---

## 7. Regression & Integrity Suite Verification

- **CAP-007 Scale Retrieval Integrity Suite**: `pytest tests/verification/test_scale_retrieval_cap007.py` $\implies$ **6/6 passed** (1.38s)
- **CAP-007 Diagnostic Robustness Suite**: `pytest tests/verification/test_scale_retrieval_robustness.py` $\implies$ **9/9 passed** (2.63s)
- **Prior Gate Verification Suites**:
  - CAP-005 Generalization: **4/4 passed**
  - CAP-006 Temporal/Replay Integrity: **6/6 passed**
- **Unit Retrieval Suite**: `pytest tests/retrieval/` $\implies$ **52/52 passed** (0.69s)
- **Linter**: `ruff check .` clean (0 errors)

---

## 8. Final Adjudication Verdict & Promotion Recommendation

**Status: PROMOTE / READY FOR CLOSURE**

1. **All 8 Gates Passing**: T1 (100%), T2 (100%), T3 (100%), T4 (100%), T5 (100%), T6 (100% mechanism-derived), T7 (19.46 ms < 50 ms), T8 (100%).
2. **Cryptographic Integrity Maintained**: All frozen step artifacts (`cases.jsonl`, `labels.jsonl`, `oracle_manifest.jsonl`, `measure_cap007.py`, `r0_baseline_results.json`, `r1_capability1_results.json`, `r2_capability2_results.json`, `r3_remediated_results.json`) verified byte-for-byte.
3. **Decoupled Robustness Proven**: Out-of-corpus negative controls with arbitrary identifiers confirm that T6 fail-closed behavior is derived strictly from traversal resource limits and boundary invariants.
4. **Clean Progression**: R0 ($87.5\%$) $\to$ R1 ($100.0\%$, token-based) $\to$ R2 ($100.0\%$, ranking solved) $\to$ R3 ($100.0\%$, genuine mechanism-derived fail-closed traversal).
