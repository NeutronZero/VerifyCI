# CAP-003A Protocol: Path-Sensitive Removal Provenance (FROZEN)

**Experiment ID**: CAP-003A  
**Corpus SHA-256**: `ad7f7f14d3de9fb12c5fd17a93ed6d58ea7d55055edb95fe74872573db88ad23`  
**Label SHA-256**: `f42410e2eb4b9711bbbe5bb46b8c9112685a6330a87c7d391dc1d2ccb5273fe3`  
**Total Cases**: 36  

## Category & Slice Distribution
- Total Cases: 36
- Verified (Positive): 13
- Fabricated (Negative): 13
- Inconclusive (Inability/Unmodeled): 10

### Slices
{
  "path_collision": 4,
  "identical_code_multifile": 4,
  "deep_deletions": 5,
  "nested_scopes": 4,
  "moved_code": 4,
  "partial_provenance": 5,
  "unicode_normalization": 4,
  "adversarial_fabrication": 6
}

## Core Invariants
1. **Absence of Provenance is Not Evidence of Absence**:
   Unmodeled code, truncated snippets, and ambiguous paths must route to `INCONCLUSIVE` (`established=False`), never `FAIL` and never `PASS`.
2. **Path Sensitivity**:
   Path identity is repository-root relative. Suffix collisions (`app/models.py` vs `core/models.py`) must never falsely match.
3. **Deep Removals Beyond 2,000 Chars**:
   Legitimate removals in large entities must verify when complete provenance exists, eliminating the legacy 2,000-character snippet truncation limitation.
4. **Anti-Circularity**:
   Gold labels are sealed before R1 redesign implementation. No case may be altered or reclassified after observing results.
