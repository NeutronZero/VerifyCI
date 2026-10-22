# Deletion Oracle Review Record

**Status: FROZEN FOR PRE-IMPLEMENTATION M2 WORK (Remediated with Unified Reference Model and AST Parsing).**

## Freeze record

- Governing topic: VerifyCI v3.1.10 design §11.3 and §16, including the M2 scenario list and stated defect/outcome semantics.
- Scope of this contribution: corpus data, schema/AST validator, and digest inventory only.
- Cases: 18, with unique IDs and explicit base/head source snapshots.
- Production implementation used to generate labels: **No**.
- Runtime oracle extraction used to generate labels: **No**.
- Validator dependencies: Python standard library only (`ast`, `hashlib`, `json`, `re`, `pathlib`) + `pytest`; no import from `verifyci`.
- Release qualification: **Not established.**

## Reviewed contracts & remediation details

- [x] **Unified reference taxonomy**: Finding witnesses and references use the standard reference kinds (`import`, `reexport`, `export`, `__all__`, `entrypoint`, `public_api`, `dynamic`).
- [x] **Test-only reference model**: `DEL-PY-006` uses standard reference kind `import`. Tests count as live by default; importing a removed symbol in a test file is a head reference to a missing definition (`DEL-DANGLING-REFERENCE` / `dangling_reference`), consistent with ordinary module imports.
- [x] **Semantic `__all__` export validation**: `DEL-PY-007` distinguishes the removed function definition from the export list. The validator parses the Python AST to confirm that `create_session` is absent from head function declarations while present as a string constant within `__all__ = ["create_session"]` in head AST.
- [x] **Accurate declaration validation**: Python fixtures are verified using `ast.parse` for `FunctionDef`, `AsyncFunctionDef`, and `ClassDef` at the declared base lines and their absence in head ASTs. Non-Python fixtures (TypeScript, Go) are documented and verified via lexical declaration-pattern matching.
- [x] **All three defect IDs have normative reason-code pairing**:
  - `DEL-REACHABLE-SYMBOL` $\leftrightarrow$ `symbol_live`
  - `DEL-DANGLING-REFERENCE` $\leftrightarrow$ `dangling_reference`
  - `DEL-DYNAMIC-REFERENCE` $\leftrightarrow$ `dynamic_reference_removed`
- [x] **Coverage limitations**: `dynamic_target_unresolved` yields `INCONCLUSIVE` / `Coverage.PARTIAL` with 0 false findings.
- [x] **Controls**: Unused private removal and rename-with-updated-references are clean controls (`PASS`, `COMPLETE`). Excluded generated path and no-removal cases establish `NOT_APPLICABLE`. Unsupported Go syntax yields `INCONCLUSIVE` / `Coverage.UNKNOWN`.
- [x] **SHA256SUMS inventory**: Covers `cases.jsonl`, `CORPUS_SPEC.md`, and `ORACLE_REVIEW.md`.
- [x] **Isolation**: No M0 files and no frozen M1 corpus files are modified.

## Validator boundaries and manual oracle review

The independent validator establishes corpus integrity, AST declaration consistency in Python, lexical coordinate token existence, and internal oracle schema consistency. It does not perform whole-program reference index construction or cross-file type resolution (which are the responsibilities of the M2 production check). Full semantic reference resolution and reachability claims were verified via manual oracle review against §11.3 before freeze. Any future oracle modification requires a revised review record and new SHA256 digests.
