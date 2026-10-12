# CAP-013 Benchmark Results: Differential, Property-Based, and Mutation Benchmark

## 1. Cryptographic Coordinates & Environment
- **Experiment ID**: CAP-013
- **Provenance Commit**: `f32b640164e63d777fb2300c142d54d5ab0c00f0` (dirty: True)
- **Default Seed**: 42
- **Platform**: `Windows-11-10.0.26300-SP0`

## 2. Gates Table with Predeclared Thresholds

| Gate | Predeclared Threshold | Measured Value | Classification |
|---|---|---|---|
| Critical Mutation Kill Rate | = 1.0000 (100%) | 1.0 | Established |
| Incorrect PASS Rate | = 0.0000 (0%) | 0.0 | Established |
| Oracle Disagreement Rate | = 0.0000 | 0.0 | Established |
| False Decline Rate | <= 0.0500 | 0.0 | Established |


## 3. Critical-Mutation Kill Table

| Mutation ID | Target Subsystem | Description | Classification |
|---|---|---|---|
| `MUT-01_EDGE_DIRECTION_FLIP` | `verifyci.retrieval.blast_radius` | Inverted caller->callee direction in call-graph traversal | **KILLED** |
| `MUT-02_MISSING_LINEAGE_LINK` | `verifyci.verification.removal` | Removed security check with missing lineage link / receipt | **KILLED** |
| `MUT-03_ALTERED_ARG_VALUE` | `verifyci.verification.call_semantics` | Mutated strict=True to strict=False in function invocation | **KILLED** |
| `MUT-04_PATH_COLLISION` | `verifyci.verification.diffmap` | Identical file basenames in separate subsystem directories | **KILLED** |
| `MUT-05_RELAXED_FAIL_CLOSED_CHECK` | `verifyci.interface.ingress` | Malformed corrupt hunk header injected into verification ingress | **KILLED** |
| `EQUIV-01_WHITESPACE_REORDER` | `formatting` | Benign whitespace comment reordering | **EQUIVALENT** |

## 4. Incorrect-PASS List
*None (0 incorrect passes observed across all generated properties and injected mutations).*

## 5. Mutation Accounting Analysis (P1-5)
- All 5 critical mutations were executed in isolated sandboxes and successfully killed.
- 1 equivalent refactoring mutation was explicitly classified as `equivalent`.
- Fixed-seed determinism verified: repeated runs produce identical metrics.
