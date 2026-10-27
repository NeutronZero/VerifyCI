# M2 Deletion Corpus Contract

**Milestone:** VerifyCI v3.1.10 M2 — Deletion Analysis
**Status:** Frozen pre-implementation oracle
**Scope:** Corpus and independent data validator only. No deletion engine, reference indexer, or production code is changed by this contribution.

## Normative outcomes

The oracle covers the three declared defects from §11.3 and §16:

- `DEL-REACHABLE-SYMBOL` / `symbol_live`: removed symbol remains reachable through an entrypoint, export, public API, or re-export/live reference.
- `DEL-DANGLING-REFERENCE` / `dangling_reference`: a head reference names a symbol with no head definition.
- `DEL-DYNAMIC-REFERENCE` / `dynamic_reference_removed`: a dynamic lookup is proven to refer to the removed symbol.

An unresolved dynamic target is a coverage limitation, not a defect ID: it yields `INCONCLUSIVE`, `Coverage.PARTIAL`, and `dynamic_target_unresolved`. Relevant deletion in an unsupported language yields `INCONCLUSIVE` with `Coverage.UNKNOWN` and `unsupported_language`. Uncertainty must not be treated as `PASS`.

## Reference taxonomy and model

Finding witnesses and references conform to a unified taxonomy across production and test code:

- `import`: static import of a module or qualified symbol in source or test files. Test references count as live by default and use standard `import` / `call` reference modeling without an artificial `test_import` discriminator. In `DEL-PY-006`, a deleted function imported by a test file is a head reference to a missing definition (`DEL-DANGLING-REFERENCE`).
- `reexport`: explicit module or package re-export (e.g. `__init__.py` or TypeScript barrel).
- `export`: TypeScript/JavaScript export statement (default or named).
- `__all__`: explicit export listed in Python module `__all__`. In `DEL-PY-007`, maintaining a removed symbol name in `__all__` keeps the symbol declared reachable as an export (`DEL-REACHABLE-SYMBOL`).
- `entrypoint`: symbol declared as an entrypoint by policy or metadata.
- `public_api`: symbol declared as part of the public API by policy.
- `dynamic`: dynamic member lookup / dispatch site proven to target the removed symbol (e.g. literal `getattr`).

## Candidate corpus

There are 18 frozen cases, authored against the design scenario list before executing any implementation:

1. Unused private symbol removal (`DEL-PY-001` -> `PASS`, `COMPLETE`).
2. Removal of a target-base public API symbol (`DEL-PY-002` -> `FAIL`, `symbol_live`).
3. Re-export through Python `__init__.py` (`DEL-PY-003` -> `FAIL`, `symbol_live`).
4. Rename with all references updated (`DEL-PY-004` -> `PASS`, `COMPLETE`).
5. Rename with a missed import/reference (`DEL-PY-005` -> `FAIL`, `dangling_reference`).
6. Test-only reference with missing definition (`DEL-PY-006` -> `FAIL`, `dangling_reference`, `import` reference kind).
7. Stale `__all__` entry (`DEL-PY-007` -> `FAIL`, `symbol_live`, `__all__` reference kind).
8. TypeScript default export still consumed (`DEL-TS-001` -> `FAIL`, `symbol_live`).
9. Deleted module with dangling import (`DEL-PY-008` -> `FAIL`, `dangling_reference`).
10. Literal `getattr` resolved to a removed method (`DEL-PY-009` -> `FAIL`, `dynamic_reference_removed`).
11. Computed `getattr` with unresolved target (`DEL-PY-010` -> `INCONCLUSIVE`, `PARTIAL`, `dynamic_target_unresolved`).
12. String-key dispatch with unresolved target (`DEL-PY-011` -> `INCONCLUSIVE`, `PARTIAL`, `dynamic_target_unresolved`).
13. Generated-path exclusion (`DEL-PY-012` -> `NOT_APPLICABLE`, `COMPLETE`).
14. Multi-file package with re-export and consumer reference (`DEL-PY-013` -> `FAIL`, `symbol_live` + `dangling_reference`).
15. TypeScript barrel re-export (`DEL-TS-002` -> `FAIL`, `symbol_live`).
16. Policy-declared entrypoint removal (`DEL-PY-014` -> `FAIL`, `symbol_live`).
17. Relevant removal in unsupported Go syntax (`DEL-GO-001` -> `INCONCLUSIVE`, `UNKNOWN`, `unsupported_language`).
18. No removed symbols (`DEL-PY-015` -> `NOT_APPLICABLE`, `COMPLETE`).

## Oracle format and independent validator scope

Each JSONL row is hand-authored and contains exact base/head file contents, an optional target-base policy model, removed symbol identities and base declaration coordinates, expected outcome/coverage/reason codes, normalized defect labels, and source-level witness coordinates. Embedded fixture text is immutable and UTF-8. File paths are repository-relative POSIX paths.

The independent validator (`tests/v3/test_deletion_corpus.py`) enforces:
1. **Python AST validation**: Uses Python standard library `ast.parse` to verify that removed symbols are true AST declarations (`FunctionDef`, `AsyncFunctionDef`, `ClassDef`) at their declared base lines, asserts that they are completely absent from head ASTs, and verifies that `__all__` export lists are syntactically parsed assignments containing the removed symbol literal.
2. **Declaration-pattern matching for non-Python fixtures**: Uses regex pattern checks for TypeScript and Go declarations where Python AST does not apply.
3. **Witness coordinates and tokens**: Validates 1-indexed lines and token presence in base and head fixture snapshots.
4. **Outcome and fail-closed contracts**: Validates outcome/coverage pairings, applicability evidence, and defect/reason-code bijection.

The independent validator does not import or execute VerifyCI check, frontend, scope, index, scheduler, or orchestration code.

## Evaluation contract

- Outcome/coverage/reason-code agreement: 100% on every case.
- Coverage classification: complete controls remain complete; unresolved dynamic targets are PARTIAL; unsupported relevant language is UNKNOWN.
- Blocking finding precision: 1.0 on the frozen corpus.
- Overall recall: at least 0.95, plus 1.0 coverage agreement; per-defect thresholds must be reported rather than hidden by an aggregate.
- Every blocking finding must identify the removed symbol and a source-level witness.
- Corpus edits after this freeze require a new explicit oracle-review record and inventory digest. Production output may not be used to rewrite expected labels.

## Explicit limits

This is a finite, hand-authored corpus. Conformance is not a general accuracy guarantee over arbitrary repositories. The standalone validator establishes structural, lexical, and AST pattern conformance; it does not perform whole-program reference index resolution or prove that graph search is complete. Semantic validity of reference closures is established by manual oracle review. Release approval is separate from implementation CI.
