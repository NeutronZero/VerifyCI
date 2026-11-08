# Semantic Oracle Review Record

**Status: FROZEN FOR PRE-IMPLEMENTATION M4 WORK.**

## Freeze record

- Governing topic: VerifyCI v3.1.10 design §11.5 and §16, including the M4 scenario list and defect/outcome semantics.
- Scope of this contribution: corpus data, independent schema/AST validator, and checksum inventory only.
- Cases: 18, with unique IDs and explicit base/head source snapshots.
- Production implementation used to generate labels: **No**.
- Runtime oracle extraction used to generate labels: **No**.
- Validator dependencies: Python standard library only (`ast`, `hashlib`, `json`, `re`, `pathlib`) + `pytest`; no import from `verifyci`.
- Release qualification: **Not established.**

## Reviewed contracts

- [x] **Defect IDs & reason code bijection**:
  - `SEM-GUARD-REMOVED` $\leftrightarrow$ `guard_removed` (evidence kind: `solver`)
  - `SEM-GUARD-WEAKENED` $\leftrightarrow$ `guard_weakened` (evidence kind: `solver`)
  - `SEM-GUARD-INVERTED` $\leftrightarrow$ `guard_inverted` (evidence kind: `solver`)
  - `SEM-BINDING-SWAP` $\leftrightarrow$ `binding_swap` (evidence kind: `solver`)
  - `SEM-EXCEPTION-REMOVED` $\leftrightarrow$ `exception_removed` (evidence kind: `solver`)
- [x] **Semantic divergence scenarios**:
  - Guard removed with sink reachable is `SEM-GUARD-REMOVED` (`SEM-PY-001`).
  - Boundary condition relaxed is `SEM-GUARD-WEAKENED` (`SEM-PY-002`).
  - Polarity inverted is `SEM-GUARD-INVERTED` (`SEM-PY-003`).
  - Call argument position swap is `SEM-BINDING-SWAP` (`SEM-PY-004`).
  - Policy-protected error path removed is `SEM-EXCEPTION-REMOVED` (`SEM-PY-005`).
  - Return tuple swap is `SEM-BINDING-SWAP` (`SEM-PY-015`).
  - Nested guards weakened is `SEM-GUARD-WEAKENED` (`SEM-PY-016`).
  - Short-circuit null guard removed is `SEM-GUARD-REMOVED` (`SEM-PY-017`).
  - TypeScript guard removed is `SEM-GUARD-REMOVED` (`SEM-TS-001`).
- [x] **Negative & applicability controls**:
  - Guard boundary strengthened without unauthorized reachability yields `PASS` (`SEM-PY-006`).
  - Guard and effect moved together preserving path conditions yields `PASS` (`SEM-PY-007`).
  - Dead guard removal (UNSAT condition) yields `PASS` (`SEM-PY-008`).
  - Argument swap with callee parameter swap coordinated yields `PASS` (`SEM-PY-009`).
  - Equivalent Boolean logic refactor yields `PASS` (`SEM-PY-010`).
  - Comment/docstring only edits yield `NOT_APPLICABLE` (`SEM-PY-014`).
- [x] **Fail-closed coverage limitations**:
  - Dynamic `eval` call yields `INCONCLUSIVE` / `Coverage.PARTIAL` (`dynamic_call`) (`SEM-PY-011`).
  - Unknown decorator yields `INCONCLUSIVE` / `Coverage.PARTIAL` (`unknown_decorator`) (`SEM-PY-012`).
  - Unsupported language edits (Go) yield `INCONCLUSIVE` / `Coverage.UNKNOWN` (`unsupported_language`) (`SEM-PY-013`).
- [x] **SHA256SUMS inventory**: Covers `cases.jsonl`, `CORPUS_SPEC.md`, and `ORACLE_REVIEW.md`.
- [x] **Isolation**: M0, M1, M2, and M3 files and frozen corpora remain strictly untouched.

## Validator boundaries and manual oracle review

The independent validator establishes corpus integrity, AST syntax consistency, lexical coordinate token existence, and internal oracle schema consistency. It does not invoke Z3 or execute symbolic execution. Full path divergence and solver satisfaction claims were verified via manual oracle review against §11.5 before freeze. Any future oracle modification requires an updated review record and new SHA256 digests.
