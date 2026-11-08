# Security Oracle Review Record

**Status: FROZEN FOR PRE-IMPLEMENTATION M4 WORK.**

## Freeze record

- Governing topic: VerifyCI v3.1.10 design §11.6 and §16, including the M4 scenario list and defect/outcome semantics.
- Scope of this contribution: corpus data, independent schema/AST validator, and checksum inventory only.
- Cases: 22, with unique IDs and explicit base/head source snapshots.
- Production implementation used to generate labels: **No**.
- Runtime oracle extraction used to generate labels: **No**.
- Validator dependencies: Python standard library only (`ast`, `hashlib`, `json`, `re`, `pathlib`) + `pytest`; no import from `verifyci`.
- Release qualification: **Not established.**

## Reviewed contracts

- [x] **Defect IDs & reason code bijection**:
  - `SEC-SECRET` $\leftrightarrow$ `secret_detected` (evidence kind: `secret_validation`)
  - `SEC-SECRET-TO-SINK` $\leftrightarrow$ `secret_to_sink` (evidence kind: `taint_path`)
  - `SEC-TAINT-TO-SINK` $\leftrightarrow$ `taint_to_sink` (evidence kind: `taint_path`)
  - `SEC-DANGEROUS-CALL` $\leftrightarrow$ `dangerous_call` (evidence kind: `call_site`)
- [x] **Provider secrets and formats**:
  - AWS access key format (`SEC-001`).
  - GitHub PAT format (`SEC-002`).
  - Slack token format (`SEC-003`).
  - Stripe live secret key format (`SEC-004`).
  - OpenAI API key format (`SEC-005`).
  - Google Cloud API key format (`SEC-006`).
  - PEM private key structure (`SEC-007`).
  - Structural JWT token (`SEC-008`).
  - Database URI with embedded credentials (`SEC-009`).
  - Generic high-entropy assignment with secret variable naming (`SEC-010`).
- [x] **Secret-to-sink flows**:
  - Direct secret passed into logging sink (`SEC-019`) -> `FAIL` / `SEC-SECRET-TO-SINK`.
  - Secret assigned to variable and propagated to sink (`SEC-020`) -> `FAIL` / `SEC-SECRET-TO-SINK`.
  - Secret passed to imported alias of logging sink (`SEC-021`) -> `FAIL` / `SEC-SECRET-TO-SINK`.
  - Newly introduced secret variable consumed by existing unchanged sink (`SEC-022`) -> `FAIL` / `SEC-SECRET-TO-SINK`.
- [x] **Negative, placeholder, and allowlist controls**:
  - Placeholder secret values (`SEC-011`) ignored -> `PASS` / `COMPLETE`.
  - Policy allowlisted fixture paths (`SEC-012`) ignored -> `PASS` / `COMPLETE`.
  - Binary-only changes without text files (`SEC-013`) -> `NOT_APPLICABLE` / `COMPLETE`.
- [x] **Dangerous calls**:
  - Built-in dangerous call `eval` (`SEC-014`) -> `FAIL` / `SEC-DANGEROUS-CALL`.
  - Custom policy-forbidden call (`SEC-015`) -> `FAIL` / `SEC-DANGEROUS-CALL`.
- [x] **Taint sub-analysis & fail-closed boundaries**:
  - Same-line source-to-sink flow (`SEC-016`) -> `FAIL` / `SEC-TAINT-TO-SINK`.
  - Unresolved source alone without resolved flow (`SEC-017`) -> `INCONCLUSIVE` / `Coverage.PARTIAL` (`taint_path_unresolved`).
  - Unsupported language under configured taint policy (`SEC-018`) -> `INCONCLUSIVE` / `Coverage.UNKNOWN` (`unsupported_language`).
- [x] **Redaction 1.0**:
  - 100% redaction verification: no raw secret values appear in finding evidence payloads or user-facing messages.
- [x] **SHA256SUMS inventory**: Covers `cases.jsonl`, `CORPUS_SPEC.md`, and `ORACLE_REVIEW.md`.
- [x] **Isolation**: M0, M1, M2, and M3 files and frozen corpora remain strictly untouched.

## Validator boundaries and manual oracle review

The independent validator establishes corpus integrity, AST syntax consistency in non-binary Python files, coordinate token existence, redaction 1.0 enforcement, and internal oracle schema consistency. Full pattern-matching, taint flow, and dangerous-call detections were verified via manual oracle review against §11.6 before freeze. Any future oracle modification requires an updated review record and new SHA256 digests.
