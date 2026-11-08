# M4 Semantic Corpus Specification

**Milestone:** VerifyCI v3.1.10 M4 — Semantic Analysis & Path Divergence  
**Status:** Frozen pre-implementation oracle  
**Scope:** Corpus and independent data validator only. No production semantic engine or solver code is changed by this contribution.

## Normative outcomes

The oracle covers the five declared defects from §11.5 and §16 of the v3.1.10 design specification:

- `SEM-GUARD-REMOVED` / `guard_removed`: protected guard removed while its protected effect remains reachable. Evidence kind: `solver` with IR-level divergence witness.
- `SEM-GUARD-WEAKENED` / `guard_weakened`: boundary condition relaxed so the effect becomes reachable for previously rejected inputs. Evidence kind: `solver`.
- `SEM-GUARD-INVERTED` / `guard_inverted`: branch condition polarity reverses, changing which branch protects the effect. Evidence kind: `solver`.
- `SEM-BINDING-SWAP` / `binding_swap`: call arguments or returned tuple elements swapped while callee/caller contract is unchanged. Evidence kind: `solver`.
- `SEM-EXCEPTION-REMOVED` / `exception_removed`: policy-protected error path removed while its trigger remains reachable. Evidence kind: `solver`.

Coverage limitations:
- Dynamic calls, reflection, or opaque constructs yield `INCONCLUSIVE` with `Coverage.PARTIAL` (`dynamic_call`).
- Unknown decorators altering function semantics yield `INCONCLUSIVE` with `Coverage.PARTIAL` (`unknown_decorator`).
- Relevant code edits in an unsupported language yield `INCONCLUSIVE` with `Coverage.UNKNOWN` (`unsupported_language`).
- Uncertainty or solver budget exhaustion must not be treated as `PASS`.

## Reference and witness taxonomy

Finding witnesses conform to §11.5:
- `solver`: Z3-derived model providing a concrete input assignment that demonstrates divergence between base and head execution paths.
- `witness_level`: `ir` (IR/AST instruction span and replay-validated divergence trace).

## Candidate corpus

There are 18 frozen cases:

1. `SEM-PY-001` (`guard_removed_with_sink_reachable`): Removing guard protecting sensitive effect -> `FAIL`, `SEM-GUARD-REMOVED` / `guard_removed`.
2. `SEM-PY-002` (`guard_boundary_weakened`): Relaxing numeric or threshold boundary condition -> `FAIL`, `SEM-GUARD-WEAKENED` / `guard_weakened`.
3. `SEM-PY-003` (`guard_polarity_inverted`): Reversing guard polarity -> `FAIL`, `SEM-GUARD-INVERTED` / `guard_inverted`.
4. `SEM-PY-004` (`call_argument_binding_swap`): Swapping argument positions to unchanged callee -> `FAIL`, `SEM-BINDING-SWAP` / `binding_swap`.
5. `SEM-PY-005` (`protected_exception_removed`): Removing policy-protected raise path -> `FAIL`, `SEM-EXCEPTION-REMOVED` / `exception_removed`.
6. `SEM-PY-006` (`guard_strengthened_safe`): Strengthening guard boundary (no unauthorized access) -> `PASS`, `Coverage.COMPLETE`.
7. `SEM-PY-007` (`guard_and_effect_moved_together_safe`): Moving guard and effect together preserving path conditions -> `PASS`, `Coverage.COMPLETE`.
8. `SEM-PY-008` (`dead_guard_removal_unsat_safe`): Removing mathematically unreachable guard (UNSAT) -> `PASS`, `Coverage.COMPLETE`.
9. `SEM-PY-009` (`argument_swap_with_callee_also_swapped_safe`): Coordinated argument and parameter swap -> `PASS`, `Coverage.COMPLETE`.
10. `SEM-PY-010` (`equivalent_refactor_safe`): Equivalent Boolean logic expression -> `PASS`, `Coverage.COMPLETE`.
11. `SEM-PY-011` (`dynamic_call_eval_gap`): Dynamic call / `eval` preventing static path resolution -> `INCONCLUSIVE`, `Coverage.PARTIAL` (`dynamic_call`).
12. `SEM-PY-012` (`unknown_decorator_opacity_gap`): Unknown decorator altering semantics -> `INCONCLUSIVE`, `Coverage.PARTIAL` (`unknown_decorator`).
13. `SEM-PY-013` (`unsupported_language_scope_gap`): Modified function in Go -> `INCONCLUSIVE`, `Coverage.UNKNOWN` (`unsupported_language`).
14. `SEM-PY-014` (`no_body_changes_not_applicable`): Comment/docstring only edits -> `NOT_APPLICABLE`, `Coverage.COMPLETE`.
15. `SEM-PY-015` (`return_tuple_swap_break`): Swapping returned tuple elements -> `FAIL`, `SEM-BINDING-SWAP` / `binding_swap`.
16. `SEM-PY-016` (`nested_guards_weakened`): Removing inner condition in nested guards -> `FAIL`, `SEM-GUARD-WEAKENED` / `guard_weakened`.
17. `SEM-PY-017` (`short_circuit_guard_removed`): Removing null-check before property access -> `FAIL`, `SEM-GUARD-REMOVED` / `guard_removed`.
18. `SEM-TS-001` (`typescript_guard_removed`): Removing role guard in TypeScript -> `FAIL`, `SEM-GUARD-REMOVED` / `guard_removed`.

## Independent validator scope

The independent validator (`tests/v3/test_semantic_corpus.py`):
1. Uses Python standard library only (`ast`, `hashlib`, `json`, `pathlib`, `re`) + `pytest`.
2. Validates `SHA256SUMS` inventory across `cases.jsonl`, `CORPUS_SPEC.md`, and `ORACLE_REVIEW.md`.
3. Verifies Python AST syntax and statement integrity in fixture sources.
4. Validates line numbers and witness coordinate tokens.
5. Validates fail-closed outcome mappings, coverage categories, and defect/reason-code bijection.

## Explicit limits

This is a finite, hand-authored corpus. Conformance against this frozen suite is not a general equivalence guarantee across arbitrary external repositories. Full semantic evaluation and benchmark execution are validated separately by the production engine under test. Release approval remains separate from implementation CI.
