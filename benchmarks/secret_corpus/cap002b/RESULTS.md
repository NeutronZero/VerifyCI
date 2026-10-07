# CAP-002B Benchmark Results

**Experiment**: CAP-002B (Provenance-Aware Multi-Signal Secret Detection)  
**Corpus SHA-256**: `b6c7df17e334f6847453012fe3a05bae82181a31411039f7d724df1a4a0ff65c`  
**Labels SHA-256**: `6f7bc1edb7ff282b93b70e403830e199faab652f91d43753f3d97f1f1f4ac8f8`  
**Cases Count**: 35  

## Comparative Metrics

| Metric | D0 (Legacy Regex) | D1 (Betterleaks 1.9.0) | D2 (Redesigned VerifyCI) |
| :--- | :---: | :---: | :---: |
| **Recall** | 0.3478 | 0.4348 | **0.8696** |
| **Precision** | 0.8 | 1.0 | **1.0** |
| **False Acceptance Rate (FAR)** | 0.1667 | 0.0 | **0.0** |
| **False Reject Rate (FRR)** | 0.6522 | 0.5652 | **0.1304** |
| **Overall Agreement** | 0.5143 | 0.6286 | **0.9143** |
| **Name-Independent Recall** | 0.2857 | 0.4286 | **0.7143** |
| **Encoded Recovery** | 0.0 | 0.3333 | **1.0** |
| **Composite Recovery** | 0.5 | 0.5 | **1.0** |
| **Redaction Violations** | 0 | 0 | **0** |
| **Incomplete Evaluations** | 0 | 0 | **0** |

## Per-Case Comparison Summary

- Total Cases: 35
- Disagreement Cases: 21
- D2 Resolution of CAP-002 Falsifiers:
  - `B-ID-01` (`pwd = "sk-live-..."`): D0 = False (miss), D1 = False (miss), D2 = True (detected).
  - `B-ID-02` (`x = "ghp_..."`): D0 = False (miss), D1 = True (detected), D2 = True (detected).
  - `B-ENC-01` (Base64 OpenAI key): D0 = False (miss), D1 = False (miss), D2 = True (detected).
  - `B-ENC-02` (Hex OpenAI key): D0 = False (miss), D1 = True (detected), D2 = True (detected).
  - `B-ENC-03` (Double Base64 GitHub token): D0 = False (miss), D1 = False (miss), D2 = True (detected).

## Statistical Qualifications & Scope Boundaries

- **Sample Size**: 35 held-out cases (23 positive, 12 negative).
- **Sampling Uncertainty (Approx. 95% Wilson Intervals)**:
  - D2 Recall: **67.9% – 95.5%** (20/23 observed = 86.96%)
  - D2 Precision: **83.9% – 100.0%** (20/20 observed = 100.00%)
  - Observed FAR: **0.0000** (0/12 negatives). Zero observed false acceptance on this frozen corpus is an empirical result of the evaluated test paths, not proof of population-level FAR = 0%.
- **Redaction Safety**: No secret material leakage was observed across the specified redaction/evidence test surface, including recursive serialized-output inspection.
- **Resource Bounds**: The tested execution paths enforce all configured budgets (lines, candidates, transform depth, timeouts), preventing observed unbounded execution.
- **Falsifier Resolution**: D2 resolves the previously isolated `pwd` falsifier on the frozen CAP-002B corpus (`B-ID-01`), detecting the case through value-first token-structure analysis where both D0 and D1 missed it.
- **Promotion Scope**: D2 is promoted as the canonical CAP-002B detector capability under the frozen contract. The 35-case corpus serves as established benchmark evidence rather than a claim of universal detection completeness.

## Final Audit Conclusion Gate

```text
CAP-002B
──────────────────────────────────────────────
Decision:              PROMOTE
Status:                ESTABLISHED

D2:
  Recall:              0.8696 (20/23)
  Precision:           1.0000 (20/20)
  Observed FAR:        0.0000 (0/12)
  FRR:                 0.1304
  Agreement:           0.9143 (32/35)

Falsifier:
  CAP-002 pwd case    RESOLVED on frozen corpus

Safety:
  Secret leakage      NOT OBSERVED on tested surfaces
  Resource bounds     ENFORCED on tested execution paths

Integrity:
  Corpus frozen       YES
  Labels frozen       YES
  CAP-002 preserved   YES
  Clean-room          YES
  D1 PASS authority   NO

Evidence boundary:
  Established only for the frozen evaluation surface.
  Universal completeness and population FAR=0 remain UNESTABLISHED.
──────────────────────────────────────────────
```
