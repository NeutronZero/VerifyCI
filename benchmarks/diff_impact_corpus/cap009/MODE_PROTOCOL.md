# CAP-009 Protocol: Diff-to-Impact Verification (FROZEN)

**Experiment ID**: CAP-009  
**Corpus SHA-256**: `f588414156bd2eedbedbf94f5b7451cb1fa1939b05710a270cd72c7de74b7580`  
**Label SHA-256**: `6e6d2e5e3f74bf2e7e2a664782ca62eccbb1efd9f0be51f5ec4e9922e24aa774`  
**Total Cases**: 225  

## Slice Distribution
{
  "pure_insertions": 25,
  "deletions": 25,
  "multi_hunk": 25,
  "renames": 25,
  "nested_scopes": 25,
  "decorators": 25,
  "same_basename_collisions": 25,
  "mixed_language": 25,
  "adversarial_critical": 25
}

## Core Invariants
1. **Zero False Passes on Critical Adversarial Cases**: Basename collisions and rename mismatches must never falsely seed collision entities.
2. **>=95% Seed Precision and Recall**: Representative slices accurately map diff hunks to AST entity IDs.
3. **>=95% Impact Precision and Recall**: Downstream call-graph blast radius matches ground-truth traversal reachability.
4. **Oracle Independence (P0-1)**: Ground truth authored independently without production diffmap.
