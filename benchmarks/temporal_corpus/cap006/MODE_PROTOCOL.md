# CAP-006 Protocol: Temporal Lineage & Multi-Branch Replay Attestation (FROZEN)

**Experiment ID**: CAP-006  
**Corpus SHA-256**: `d89ae5f9d641a209ef525f64dd6f0b060e3f8db8be1891944efdba3877298b1a`  
**Label SHA-256**: `5bfa328a9f5f1f96cec1c3a1e674ee22358999dd9f69857603c95d34121a003c`  
**Oracle Manifest SHA-256**: `99ea4c3b128f74d82338c9416f2929088de0185ac112d34cb68569b562c0baf8`  
**Total Cases**: 64  
**Total Slices**: 8  

## Evaluation Gates (T1–T8)
- **T1: Incremental Replay Equivalence**: CanonicalSemanticGraph(IncrementalReplay(H)) == CanonicalSemanticGraph(CleanSnapshot(H)).
- **T2: Rename Lineage Continuity**: Entity identity survives file and symbol renames without duplicate live intervals.
- **T3: Revert Cycle Correctness**: Linear and cyclic reverts restore exact historical states while recording lineage.
- **T4: Branch Divergence Isolation**: Interleaved multi-branch ingestion guarantees zero cross-branch graph contamination.
- **T5: Merge Attestation Determinism**: Two-parent, fast-forward, and criss-cross merges yield deterministic canonical semantic graphs.
- **T6: Anchor Point-in-Time Stability**: Historical queries (`as_of`) remain invariant across subsequent ingestion.
- **T7: Temporal Fail-Closed Integrity**: Corrupted anchors, disconnected lineage, and cyclic anomalies strictly fail closed with INCONCLUSIVE.
- **T8: Corpus Replay Agreement**: Comprehensive agreement on frozen corpus across all 64 cases.

## Category & Slice Distribution
- Total Cases: 64
- Ground Truth PASS: 56
- Ground Truth INCONCLUSIVE (Tripwires): 8
- Ground Truth FAIL: 0

### Stratified Slices
- `rename_edit_rename_back`: 8
- `delete_and_restore`: 8
- `revert_cycles`: 8
- `cherry_pick_cross_branch`: 8
- `interleaved_branch_ingest`: 8
- `criss_cross_merges`: 8
- `stale_cache_and_idempotence`: 8
- `truncated_lineage_tripwire`: 8

## Core Protocol Locks
1. **LOCK-1 (Frozen History)**:
   Corpus and gold labels are sealed and immutable upon Step 1 commit.
2. **LOCK-2 (Independent Oracle Requirement)**:
   Ground truth was derived exclusively by the standalone independent oracle (`oracle.py`), which imports zero modules from `verifyci`.
3. **LOCK-3 (No Post-Result Relabeling)**:
   Observed measurement discrepancies cannot alter frozen cases or labels.
4. **LOCK-4 (Fail-Closed Contract)**:
   Disconnected lineage, shallow gaps, or corrupted DAG metadata must yield INCONCLUSIVE, never an invented PASS.
5. **LOCK-5 (Explicit Branch Identity Coordinates)**:
   Every case specifies explicit commit IDs, parent IDs, branches, and replay sequences.
