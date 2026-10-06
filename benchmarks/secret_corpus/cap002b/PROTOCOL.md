# CAP-002B Experiment Protocol

**Capability Experiment**: CAP-002B (Provenance-Aware Multi-Signal Secret Detection)  
**Corpus SHA-256**: `b6c7df17e334f6847453012fe3a05bae82181a31411039f7d724df1a4a0ff65c`  
**Labels SHA-256**: `6f7bc1edb7ff282b93b70e403830e199faab652f91d43753f3d97f1f1f4ac8f8`  
**Cases Count**: 35  
**Frozen At**: 2026-10-06T15:48:00Z  

## 1. Frozen Invariants & Governance

- The existing CAP-002 17-case held-out corpus (`benchmarks/patch_corpus/cap002_heldout/cases.jsonl`) remains frozen and untouched.
- The CAP-002B corpus was authored and cryptographically frozen **before** evaluating D2 implementation results.
- No detector implementation (D0, D1, D2) has access to expected labels during scanning.
- D1 is executed via a genuine external Betterleaks binary (`v1.9.0`, SHA-256: `41a3dc5e75712d52d25aa7203b0b6bc2fa9c796fe5109d3835c60226a9a69352`).
- D1 findings are recorded strictly as an external comparator; D1 is **never** used as ground truth or for D2 tuning.
- Redaction Hard Boundary: No raw secret material may ever enter persisted artifacts, evidence packs, error reports, or logs.

## 2. Comparators

1. **D0**: Baseline VerifyCI regex-based detector (`_scan_secrets`).
2. **D1**: Genuine external Betterleaks CLI executable (`betterleaks.exe 1.9.0`).
3. **D2**: Redesigned VerifyCI clean-room detector (`verifyci.secrets`).

## 3. Evaluation Slices

The 35 cases cover 7 distinct slices:
1. `identifier_independent`: Cases where credentials appear under neutral or misdirecting variable names (`pwd`, `x`, `value`, `foo`, `session_meta`, `credential_data`).
2. `provider_structured`: Provider tokens (OpenAI, Stripe, Slack, AWS, Google) and cryptographic/connection structures (PEM private keys, JWT, MongoDB URIs).
3. `encoded`: Base64, hex, and double-pass encodings, plus encoded benign text false positives.
4. `fragmented`: String concatenations, multiline parenthesized blocks, and backslash continuations.
5. `path_aware`: Production paths, configuration files, test fixture mock tokens, documentation placeholders, and hidden CI paths.
6. `false_positive`: True negatives including docstrings, Git commit SHA hashes, UUIDs, template placeholders, env lookups, dotted wiring, and graphic assets.
7. `composite`: Multi-signal evidence combining proximity context with high entropy, intrinsic tokens, and benign keyword mentions.

## 4. Metrics Evaluated

- `detection_recall`: $TP / (TP + FN)$
- `detection_precision`: $TP / (TP + FP)$
- `false_acceptance_rate`: $FP / (FP + TN)$
- `false_reject_rate`: $FN / (TP + FN)$
- `name_independent_recall`: Recall on `identifier_independent` slice
- `encoded_recovery`: Recall on `encoded` true positives
- `composite_recovery`: Recall on `composite` true positives
- `redaction_violations`: Count of unredacted raw secrets in persisted reports (must strictly be 0)
- `incomplete_evaluations`: Resource exhaustion or timeout count
