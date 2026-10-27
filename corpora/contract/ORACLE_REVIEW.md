# Contract Oracle Review Record

**Status: FROZEN FOR PRE-IMPLEMENTATION M3 WORK.**

## Freeze record

- Governing topic: VerifyCI v3.1.10 design §11.4 and §16, including the M3 scenario list and defect/outcome semantics.
- Scope of this contribution: corpus data, independent schema/AST validator, and checksum inventory only.
- Cases: 17, with unique IDs and explicit base/head source snapshots.
- Production implementation used to generate labels: **No**.
- Runtime oracle extraction used to generate labels: **No**.
- Validator dependencies: Python standard library only (`ast`, `hashlib`, `json`, `re`, `pathlib`) + `pytest`; no import from `verifyci`.
- Release qualification: **Not established.**

## Reviewed contracts

- [x] **Defect IDs & reason code bijection**:
  - `CTR-SIGNATURE-BREAK` $\leftrightarrow$ `signature_break` (evidence kind: `call_site` or `reference`)
  - `CTR-EXPORT-BREAK` $\leftrightarrow$ `export_break` (evidence kind: `reference`)
  - `CTR-CALL-INCOMPATIBLE` $\leftrightarrow$ `call_incompatible` (evidence kind: `call_site`)
- [x] **Caller and signature scenarios**:
  - Optional parameter added with default is a clean backward-compatible `PASS` (`CTR-PY-001`).
  - Removed parameter breaking live caller is `CTR-SIGNATURE-BREAK` (`CTR-PY-002`).
  - Renamed keyword parameter is `CTR-SIGNATURE-BREAK` (`CTR-PY-003`).
  - Required parameter added without default is `CTR-SIGNATURE-BREAK` (`CTR-PY-004`).
  - Async-to-sync change breaking awaiting caller is `CTR-SIGNATURE-BREAK` (`CTR-PY-005`).
  - Changed call site violating unchanged callee is `CTR-CALL-INCOMPATIBLE` (`CTR-PY-006`).
  - Public-API signature break without repo callers is `CTR-SIGNATURE-BREAK` with `reference` evidence (`CTR-PY-007`).
  - Removed export still imported by consumer is `CTR-EXPORT-BREAK` (`CTR-PY-008`).
  - Positional-only parameter violation is `CTR-SIGNATURE-BREAK` (`CTR-PY-011`).
  - TypeScript signature and export breaks covered (`CTR-TS-001`, `CTR-TS-002`).
  - Positional parameter keyword rename covered (`CTR-PY-013`).
  - Default value removal covered (`CTR-PY-014`).
- [x] **Fail-closed coverage limitations**:
  - Dynamic calls (`*args` / `**kwargs`) yield `INCONCLUSIVE` / `Coverage.PARTIAL` (`dynamic_call`) (`CTR-PY-009`).
  - Unsupported language edits (Go) yield `INCONCLUSIVE` / `Coverage.UNKNOWN` (`unsupported_language`) (`CTR-GO-001`).
- [x] **Negative & applicability controls**:
  - External-only consumer (internal symbol modified with 0 repo callers and not public API) yields `PASS` / `Coverage.COMPLETE` (`CTR-PY-010`).
  - No signature, export, or call-site change yields `NOT_APPLICABLE` / `Coverage.COMPLETE` (`CTR-PY-012`).
- [x] **SHA256SUMS inventory**: Covers `cases.jsonl`, `CORPUS_SPEC.md`, and `ORACLE_REVIEW.md`.
- [x] **Isolation**: M0, M1, and M2 files and frozen corpora remain strictly untouched.

## Validator boundaries and manual oracle review

The independent validator establishes corpus integrity, AST declaration and call-site consistency in Python, lexical coordinate token existence, and internal oracle schema consistency. It does not perform whole-program reference graph construction or cross-file type inference. Full semantic parameter binding and call-site compatibility claims were verified via manual oracle review against §11.4 before freeze. Any future oracle modification requires an updated review record and new SHA256 digests.
