# CAP-003A Benchmark Results: Path-Sensitive Removal Provenance

**Experiment**: CAP-003A  
**Corpus SHA-256**: `51a09c91d27d23af893ccafda3dbb22356bf6d8eccf1462b56d03d04e301aac7`  
**Label SHA-256**: `f42410e2eb4b9711bbbe5bb46b8c9112685a6330a87c7d391dc1d2ccb5273fe3`  
**Cases Count**: 36  

## Comparative Metrics

| Metric | R0 (Legacy Removal Checker) | R1 (Redesigned Provenance Checker) |
| :--- | :---: | :---: |
| **Overall Agreement** | 0.8611 (31/36) | **1.0000 (36/36)** |
| **Fabricated Detection (FAIL)** | 1.0000 | **1.0000 (100%)** |
| **Genuine Removal Verified** | 0.7692 | **1.0000 (100%)** |
| **Inconclusive Provenance** | 0.8000 | **1.0000 (100%)** |

## Slice Performance Breakdown

| Slice | R0 Correct / Total | R1 Correct / Total | R1 Resolution |
| :--- | :---: | :---: | :--- |
| `path_collision` | 2/4 | **4/4** | Ambiguous suffix collisions eliminated |
| `deep_deletions` | 2/5 | **5/5** | 2,000-char snippet cap overcome via line hashes |
| `identical_code_multifile` | 4/4 | **4/4** | Multi-file isolation preserved |
| `nested_scopes` | 4/4 | **4/4** | Hierarchy & enclosing scope matching |
| `moved_code` | 4/4 | **4/4** | Moved lines verified at origin |
| `partial_provenance` | 5/5 | **5/5** | Incomplete/unmodeled -> INCONCLUSIVE |
| `unicode_normalization` | 4/4 | **4/4** | NFC/NFD equivalence + homoglyph catch |
| `adversarial_fabrication` | 6/6 | **6/6** | 100% fail-closed on forged lines |

## Acceptance Gate Predicates (P1–P12)

```text
P1  Frozen corpus integrity                 PASS
P2  Frozen labels integrity                 PASS
P3  100% provenance for claimed PASS cases  PASS
P4  Fabricated removal -> FAIL              PASS (100%)
P5  Genuine removal -> VERIFIED             PASS (100% >= 95%)
P6  Unknown/incomplete provenance           PASS (never PASS)
P7  Path/entity disambiguation              PASS (100%)
P8  No retroactive corpus modification      PASS
P9  No secret/evidence leakage              PASS
P10 Resource bounds                         PASS
P11 Full regression suite                   PASS (1068 passed, 0 failed)
P12 Clean-room / provenance integrity       PASS
```

## Final Audit Conclusion Gate

```text
CAP-003A
──────────────────────────────────────────────
Decision:              PROMOTE
Status:                ESTABLISHED

R1:
  Overall Agreement:   1.0000 (36/36)
  Fabricated Catch:    1.0000 (13/13) -> FAIL
  Genuine Verified:    1.0000 (13/13) -> VERIFIED
  Inconclusive Prov:   1.0000 (10/10) -> INCONCLUSIVE

Resolved Limitations:
  Path Suffix Collision: RESOLVED (zero false matches across bare filenames)
  2,000-char Snippet Cap: RESOLVED (per-line provenance hashes remove fixed 2,000-char coverage boundary, subject to resource limits)
  Enclosing Hierarchy:   RESOLVED (innermost & nested scope verification)

Safety & Invariants:
  Incomplete Provenance: NEVER PASS (unknown != false -> INCONCLUSIVE)
  Fabricated Removals:   100% FAIL CLOSED

Integrity:
  Corpus frozen:       YES (SHA-256: 51a09c91d27d23af893ccafda3dbb22356bf6d8eccf1462b56d03d04e301aac7)
  Labels frozen:       YES (SHA-256: f42410e2eb4b9711bbbe5bb46b8c9112685a6330a87c7d391dc1d2ccb5273fe3)
  CAP-002/002B:        PRESERVED & UNTOUCHED
  Regression suite:    1068 passed, 6 skipped, 0 failed
──────────────────────────────────────────────
```
