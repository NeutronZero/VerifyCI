# M3 Contract Corpus Contract

**Milestone:** VerifyCI v3.1.10 M3 — Caller & Contract Breakage
**Status:** Frozen pre-implementation oracle
**Scope:** Corpus and independent data validator only. No contract engine, call-site analyzer, or production code is changed by this contribution.

## Normative outcomes

The oracle covers the three declared defects from §11.4 and §16 of the v3.1.10 design specification:

- `CTR-SIGNATURE-BREAK` / `signature_break`: parameter, return, async, or visibility change incompatible with a resolved caller or declared public API. Evidence kind: `call_site` (for caller breaks) or `reference` (for public-API policy declarations).
- `CTR-EXPORT-BREAK` / `export_break`: removed or renamed export still imported or declared public. Evidence kind: `reference`.
- `CTR-CALL-INCOMPATIBLE` / `call_incompatible`: changed call site disagrees with an unchanged callee. Evidence kind: `call_site`.

Coverage limitations:
- Dynamic calls (`*args` / `**kwargs`) and unresolved imports yield `INCONCLUSIVE` with `Coverage.PARTIAL` (`dynamic_call`, `unresolved_import`).
- Relevant contract edits in an unsupported language yield `INCONCLUSIVE` with `Coverage.UNKNOWN` (`unsupported_language`).
- Uncertainty must not be treated as `PASS`.

## Reference and witness taxonomy

Finding witnesses conform to §11.4:
- `call_site`: concrete call site in head code where parameter binding fails (too few arguments, too many arguments, unknown keyword, missing keyword, or async/sync divergence).
- `reference`: export or public-API declaration span where a contract break affects external/public consumers.

## Candidate corpus

There are 17 frozen cases:

1. `CTR-PY-001` (`optional_parameter_added`): Adding optional parameter with default -> `PASS`, `COMPLETE`.
2. `CTR-PY-002` (`removed_used_parameter`): Removing parameter with live caller -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.
3. `CTR-PY-003` (`keyword_parameter_renamed`): Renaming keyword parameter -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.
4. `CTR-PY-004` (`required_parameter_added_without_default`): Adding required parameter -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.
5. `CTR-PY-005` (`async_to_sync_change`): Async function changed to sync while caller awaits -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.
6. `CTR-PY-006` (`caller_only_break`): Changed call site violates unchanged callee signature -> `FAIL`, `CTR-CALL-INCOMPATIBLE` / `call_incompatible`.
7. `CTR-PY-007` (`public_api_signature_break`): Breaking signature change on policy-declared public API without internal callers -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break` (reference witness).
8. `CTR-PY-008` (`export_break_removed_export_still_imported`): Removed export still imported by consumer -> `FAIL`, `CTR-EXPORT-BREAK` / `export_break`.
9. `CTR-PY-009` (`dynamic_call_kwargs_gap`): Call site passes `**kw` preventing exact static resolution -> `INCONCLUSIVE`, `Coverage.PARTIAL` (`dynamic_call`).
10. `CTR-PY-010` (`external_only_consumer_safe`): Internal symbol modified with 0 callers and not declared public API -> `PASS`, `COMPLETE`.
11. `CTR-PY-011` (`positional_only_violation`): Positional-only parameter passed as keyword -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.
12. `CTR-TS-001` (`typescript_signature_break`): TypeScript function signature break with caller -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.
13. `CTR-TS-002` (`typescript_export_break`): TypeScript export removed while imported -> `FAIL`, `CTR-EXPORT-BREAK` / `export_break`.
14. `CTR-GO-001` (`unsupported_language_contract_scope`): Relevant change in Go -> `INCONCLUSIVE`, `Coverage.UNKNOWN` (`unsupported_language`).
15. `CTR-PY-012` (`no_contract_changes_not_applicable`): No signature, export, or call-site change -> `NOT_APPLICABLE`, `Coverage.COMPLETE`.
16. `CTR-PY-013` (`positional_parameter_keyword_rename`): Renamed positional parameter called by keyword -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.
17. `CTR-PY-014` (`default_value_removed`): Default value removed turning optional parameter into required -> `FAIL`, `CTR-SIGNATURE-BREAK` / `signature_break`.

## Independent validator scope

The independent validator (`tests/v3/test_contract_corpus.py`):
1. Uses Python standard library only (`ast`, `hashlib`, `json`, `pathlib`, `re`) + `pytest`.
2. Validates `SHA256SUMS` inventory across `cases.jsonl`, `CORPUS_SPEC.md`, and `ORACLE_REVIEW.md`.
3. Verifies Python AST syntax and call sites in fixture sources.
4. Validates line numbers and witness coordinate tokens.
5. Validates fail-closed outcome mappings, coverage categories, and defect/reason-code bijection.

## Explicit limits

This is a finite, hand-authored corpus. Conformance against this frozen suite is not a general contract-soundness guarantee across arbitrary external repositories. Full semantic evaluation and benchmark execution are validated separately by the production engine under test. Release approval remains separate from implementation CI.
