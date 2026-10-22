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

## Candidate corpus

There are 18 frozen cases, authored against the design scenario list before executing any implementation:

1. Unused private symbol removal.
2. Removal of a target-base public API symbol.
3. Re-export through Python `__init__.py`.
4. Rename with all references updated.
5. Rename with a missed import/reference.
6. Test-only reference (tests count as live by default).
7. Stale `__all__` entry.
8. TypeScript default export still consumed.
9. Deleted module with dangling import.
10. Literal `getattr` resolved to a removed method.
11. Computed `getattr` with unresolved target.
12. String-key dispatch with unresolved target.
13. Generated-path exclusion.
14. Multi-file package with re-export and consumer reference.
15. TypeScript barrel re-export.
16. Policy-declared entrypoint removal.
17. Relevant removal in unsupported Go syntax.
18. No removed symbols (positive NOT_APPLICABLE control).

## Oracle format

Each JSONL row is hand-authored and contains exact base/head file contents, an optional target-base policy model, removed symbol identities and base declaration coordinates, expected outcome/coverage/reason codes, normalized defect labels, and source-level witness coordinates. Embedded fixture text is immutable and UTF-8. File paths are repository-relative POSIX paths.

Finding evidence is sourced independently of the production check. Each finding records its defect/reason pair, removed symbol, and witness side/path/line/kind/token. The validator confirms that those tokens exist at the declared lines and that each removed symbol has a base declaration and no head declaration; it does not import or execute VerifyCI check, frontend, scope, index, scheduler, or orchestration code.

## Evaluation contract

- Outcome/coverage/reason-code agreement: 100% on every case.
- Coverage classification: complete controls remain complete; unresolved dynamic targets are PARTIAL; unsupported relevant language is UNKNOWN.
- Blocking finding precision: 1.0 on the frozen corpus.
- Overall recall: at least 0.95, plus 1.0 coverage agreement; per-defect thresholds must be reported rather than hidden by an aggregate.
- Every blocking finding must identify the removed symbol and a source-level witness.
- Corpus edits after this freeze require a new explicit oracle-review record and inventory digest. Production output may not be used to rewrite expected labels.

## Explicit limits

This is a finite, hand-authored corpus. Conformance is not a general accuracy guarantee over arbitrary repositories. The dataset oracle does not validate reference-index soundness or prove that the implementation search is complete; those require later adversarial, differential, and integration validation. Release approval is separate from implementation CI.
