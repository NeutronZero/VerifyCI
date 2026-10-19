# VerifyCI v2.3 Phase 2 Runtime-Audit Remediation

## Scope

This patch is based on the supplied `VerifyCI-refactor-kernel-redesign(1).zip` and the attached `phase1_phase2_audit_report.md`. Phase 1 reconstruction, compile-context ownership, and the mandatory-gate ledger were left unchanged.

## Findings reconciled with the supplied snapshot

The audit report describes two failures that are already corrected in this uploaded source snapshot:

- `prove_equivalence` guards optional `returns` annotations and converts each decorator to an AST dump separately; it does not pass `None` or a Python list directly to `ast.dump`.
- `_z3_make` attempts a constructor call with `ctx`, then retries without the keyword when that constructor does not accept it. The parameter Const is routed through this helper.

Those statements apply to the files in the ZIP reviewed here, not necessarily the earlier `VerifyCI-v2.3-phase1-phase2.zip` named by the report.

## Additional Phase 2 corrections

1. **Unannotated/dynamic arithmetic fails closed.** The AST evaluator previously allowed `kind is None` through its numeric projection; the integer-only U-SSA fallback could then prove equivalence outside the modeled Python input domain. A dedicated `_UnsupportedInputDomain` exception now returns `INCONCLUSIVE_UNSUPPORTED` without invoking that fallback for dynamic arithmetic, comparisons, ordering, truthiness, or unsupported identity operations.
2. **Typed numeric domains are explicit.** Recognized `int`, `bool`, and `str` annotations are handled as proof-domain assumptions; the `int` domain includes Boolean values because `bool` is a Python `int` subtype. Float annotations are not silently modeled as integers.
3. **Model extraction does not fabricate values.** The typed PyVal path now returns an inconclusive result when an integer/string model value cannot be materialized or when a parameter uses an unsupported constructor; it no longer substitutes `0` or `""` for failed extraction.
4. **Fallback solver contexts are isolated.** The U-SSA fallback now creates an explicit local Z3 context for its symbols, extractors, and solver.
5. **Regression tests added.** Added tests for unannotated parameter arithmetic abstention, continued support for annotated integer arithmetic, and `_z3_make` constructor context behavior.

## Validation performed in this environment

- `python -m compileall -q verifyci_v2 tests`: **PASS**.
- `python -m pytest tests/v2/test_v2_3_phase1_phase2.py -q`: **BLOCKED at collection** because `msgspec` is not installed.
- Dependency installation attempt: **BLOCKED** because package-index DNS/network access is unavailable.

Therefore no runtime Z3 result or full-suite pass is claimed for this patched archive. Run the focused suite and full repository suite in the project environment with the locked dependencies before merging.
