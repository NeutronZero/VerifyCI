"""Focused regressions for the VerifyCI v2.3 Phase 1/2 implementation.

These tests are intentionally separate from frozen-corpus adjudication. They
exercise implementation invariants; they do not substitute for the complete
acceptance suite.
"""
from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor

import pytest

from verifyci_v2.contracts.attestation import GateExecutionReceipt
from verifyci_v2.ingestion.compile_context import compile_file_pair
from verifyci_v2.ingestion import ssa_lower
from verifyci_v2.pipeline import (
    DiffFileEntry,
    apply_unified_diff_to_source,
    verdict_from_findings,
)
from verifyci_v2.symbolic import egglog_engine, z3_prover


def test_patch_reconstruction_checks_context_and_preserves_eol() -> None:
    base = "first\r\nsecond\r\nthird"
    good = (
        "--- a/m.py\r\n+++ b/m.py\r\n"
        "@@ -1,3 +1,3 @@\r\n"
        " first\r\n-second\r\n+changed\r\n third\r\n"
        "\\ No newline at end of file\r\n"
    )
    assert apply_unified_diff_to_source(base, good) == "first\r\nchanged\r\nthird"

    stale = (
        "--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,2 @@\n"
        " wrong-context\n-second\n+changed\n"
    )
    assert apply_unified_diff_to_source("first\nsecond\n", stale) is None


def test_patch_reconstruction_handles_zero_hunks_and_plus_prefix_source() -> None:
    insert = "--- /dev/null\n+++ b/m.py\n@@ -0,0 +1,2 @@\n+++counter\n+value = 1\n"
    assert apply_unified_diff_to_source("", insert) == "++counter\nvalue = 1\n"

    remove = "--- a/m.py\n+++ b/m.py\n@@ -1,2 +1,1 @@\n---counter\n keep\n"
    assert apply_unified_diff_to_source("--counter\nkeep\n", remove) == "keep\n"

    malformed_blank = "--- a/m.py\n+++ b/m.py\n@@ -1,1 +1,1 @@\n\n"
    assert apply_unified_diff_to_source("source\n", malformed_blank) is None


def test_from_sources_preserves_duplicate_added_lines_and_locations() -> None:
    base = "def f(x):\n    eval(x)\n    return x\n"
    head = "def f(x):\n    eval(x)\n    eval(x)\n    return x\n"
    entry = DiffFileEntry.from_sources("m.py", base, head)
    assert any(record.content.strip() == "eval(x)" for record in entry.added_line_records)
    assert len([r for r in entry.added_line_records if r.content.strip() == "eval(x)"]) == 1
    assert all(r.head_lineno > 0 and r.hunk_index >= 0 for r in entry.added_line_records)


def test_compile_pair_parses_and_lowers_each_revision_once(monkeypatch: pytest.MonkeyPatch) -> None:
    actual_parse = ast.parse
    parse_calls: list[str] = []

    def counted_parse(source: str, *args, **kwargs):
        parse_calls.append(source)
        return actual_parse(source, *args, **kwargs)

    actual_lower = ssa_lower.lower_module_to_ussa
    lower_calls: list[str] = []

    def counted_lower(file_path, tree, source, **kwargs):
        lower_calls.append(source)
        return actual_lower(file_path, tree, source, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)
    monkeypatch.setattr(ssa_lower, "lower_module_to_ussa", counted_lower)

    base = "def f(x):\n    return x\n"
    head = "def f(x):\n    return x + 1\n"
    compiled = compile_file_pair(DiffFileEntry.from_sources("m.py", base, head))

    assert compiled.syntax_error is None
    assert compiled.base_ast is not None and compiled.head_ast is not None
    assert len(parse_calls) == 2
    assert len(lower_calls) == 2
    assert compiled.base_ast.verify_unmutated()
    assert compiled.head_ast.verify_unmutated()


def test_gate_ledger_prevents_empty_findings_from_passing() -> None:
    required = {"m.py": ("RECONSTRUCTION_AND_SYNTAX", "SYMBOLIC_PROVER")}
    receipts = (GateExecutionReceipt(
        gate_id="RECONSTRUCTION_AND_SYNTAX", file_path="m.py", status="COMPLETED"
    ),)
    status, _ = verdict_from_findings((), receipts, required)
    assert status == "INCONCLUSIVE"

    complete = receipts + (GateExecutionReceipt(
        gate_id="SYMBOLIC_PROVER", file_path="m.py", status="COMPLETED"
    ),)
    status, _ = verdict_from_findings((), complete, required)
    assert status == "PASS"


def test_z3_pyval_distinguishes_return_types_and_python_equality() -> None:
    if z3_prover._z3_mod is None:
        pytest.skip("z3-solver is not installed")

    pctx = z3_prover._Z3ProofContext(timeout_ms=1000)
    false_value = pctx.boolean(False)
    zero_value = pctx.integer(0)
    eq = z3_prover._encode_py_eq(false_value, zero_value, pctx)
    solver = pctx.solver()
    solver.add(z3_prover._z3_mod.Not(eq))
    assert solver.check() == z3_prover._z3_mod.unsat

    identity_solver = pctx.solver()
    identity_solver.add(false_value.term == zero_value.term)
    assert identity_solver.check() == z3_prover._z3_mod.unsat
    none_solver = pctx.solver()
    none_solver.add(pctx.none().term == zero_value.term)
    assert none_solver.check() == z3_prover._z3_mod.unsat


def test_equivalence_proof_does_not_alias_none_bool_int_or_strings() -> None:
    if z3_prover._z3_mod is None:
        pytest.skip("z3-solver is not installed")

    prover = z3_prover.Z3SymbolicProver(timeout_ms=1000)
    cases = [
        ("return None", "return -999999"),
        ("return False", "return 0"),
        ('return "plumless"', 'return "buckeroo"'),
    ]
    for base_return, head_return in cases:
        base = f"def f():\n    {base_return}\n"
        head = f"def f():\n    {head_return}\n"
        compiled = compile_file_pair(DiffFileEntry.from_sources("m.py", base, head))
        assert compiled.syntax_error is None
        fb, fh = compiled.base_ussa["m.f"], compiled.head_ussa["m.f"]
        proof = prover.prove_equivalence(
            func_base=fb,
            func_cand=fh,
            base_fn_node=compiled.base_ast.functions_by_qname["m.f"],
            cand_fn_node=compiled.head_ast.functions_by_qname["m.f"],
        )
        assert proof.outcome == "PROVEN_DIVERGENT_SAT"
        assert proof.witness is not None


def test_python_eq_coercion_is_distinct_from_return_equivalence() -> None:
    if z3_prover._z3_mod is None:
        pytest.skip("z3-solver is not installed")

    prover = z3_prover.Z3SymbolicProver(timeout_ms=1000)
    base = "def f():\n    return False == 0\n"
    head = "def f():\n    return True\n"
    compiled = compile_file_pair(DiffFileEntry.from_sources("m.py", base, head))
    proof = prover.prove_equivalence(
        func_base=compiled.base_ussa["m.f"],
        func_cand=compiled.head_ussa["m.f"],
        base_fn_node=compiled.base_ast.functions_by_qname["m.f"],
        cand_fn_node=compiled.head_ast.functions_by_qname["m.f"],
    )
    assert proof.outcome == "PROVEN_EQUIVALENT_UNSAT"


def test_egraph_state_is_not_global_and_calls_are_thread_safe() -> None:
    assert not hasattr(egglog_engine, "_EGGLOG_CHECK_EGRAPH")
    functions = ssa_lower.lower_file_to_ussa(
        "m.py", "def f(x):\n    return x + 0\n"
    )
    fn = functions[0]
    engine = egglog_engine.EgglogEquivalenceEngine()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: engine.check_equivalence(fn, fn), range(16)))
    assert all(result.base_eclass_digest == results[0].base_eclass_digest for result in results)


def test_intent_spec_compiler_uses_context_scoped_pyval_semantics() -> None:
    if z3_prover._z3_mod is None:
        pytest.skip("z3-solver is not installed")

    from verifyci_v2.neural.spec_compiler import _ast_to_z3_val

    pctx = z3_prover._Z3ProofContext(timeout_ms=1000)
    expr = ast.parse("False == 0", mode="eval").body
    typed = _ast_to_z3_val(expr, {}, z3_prover._z3_mod, pctx)
    assert typed is not None and typed.kind == "BOOL"
    solver = pctx.solver()
    solver.add(z3_prover._z3_mod.Not(pctx.truth(typed)))
    assert solver.check() == z3_prover._z3_mod.unsat


def test_intent_compiler_can_use_preparsed_ast_without_reparsing() -> None:
    from verifyci_v2.neural.spec_compiler import IntentToSMTCompiler

    source = "def f():\n    return -1\n"
    tree = ast.parse(source)
    finding = IntentToSMTCompiler().verify_function_against_intent(
        file_path="m.py",
        source=source,
        intent_text="return must be non-negative",
        preparsed_tree=tree,
    )
    if z3_prover._z3_mod is None:
        assert not finding or all(f.verdict == "INCONCLUSIVE" for f in finding)
    else:
        assert any(f.verdict == "FAIL" for f in finding)


def test_unannotated_parameter_arithmetic_abstains_instead_of_integer_fallback() -> None:
    """Generic Python inputs must not be silently coerced by the legacy U-SSA path."""
    if z3_prover._z3_mod is None:
        pytest.skip("z3-solver is not installed")

    prover = z3_prover.Z3SymbolicProver(timeout_ms=1000)
    base = "def f(x):\n    return x + 1\n"
    head = "def f(x):\n    return 1 + x\n"
    compiled = compile_file_pair(DiffFileEntry.from_sources("m.py", base, head))
    assert compiled.syntax_error is None
    proof = prover.prove_equivalence(
        func_base=compiled.base_ussa["m.f"],
        func_cand=compiled.head_ussa["m.f"],
        base_fn_node=compiled.base_ast.functions_by_qname["m.f"],
        cand_fn_node=compiled.head_ast.functions_by_qname["m.f"],
    )
    assert proof.outcome == "INCONCLUSIVE_UNSUPPORTED"
    assert "input domain" in proof.reason or "arithmetic" in proof.reason


def test_annotated_integer_parameter_arithmetic_remains_supported() -> None:
    """The supported numeric annotation contract continues to prove simple rewrites."""
    if z3_prover._z3_mod is None:
        pytest.skip("z3-solver is not installed")

    prover = z3_prover.Z3SymbolicProver(timeout_ms=1000)
    base = "def f(x: int) -> int:\n    return x + 1\n"
    head = "def f(x: int) -> int:\n    return 1 + x\n"
    compiled = compile_file_pair(DiffFileEntry.from_sources("m.py", base, head))
    assert compiled.syntax_error is None
    proof = prover.prove_equivalence(
        func_base=compiled.base_ussa["m.f"],
        func_cand=compiled.head_ussa["m.f"],
        base_fn_node=compiled.base_ast.functions_by_qname["m.f"],
        cand_fn_node=compiled.head_ast.functions_by_qname["m.f"],
    )
    assert proof.outcome == "PROVEN_EQUIVALENT_UNSAT"


def test_z3_constructor_fallback_keeps_explicit_context() -> None:
    """Z3 constructors with inferred contexts still create terms in the proof context."""
    if z3_prover._z3_mod is None:
        pytest.skip("z3-solver is not installed")

    z3 = z3_prover._z3_mod
    pctx = z3_prover._Z3ProofContext(timeout_ms=1000)
    constant = z3_prover._z3_make(z3.Const, "ctx_regression", pctx.pyval, ctx=pctx.ctx)
    int_sort = z3.IntSort(ctx=pctx.ctx)
    function = z3_prover._z3_make(z3.Function, "ctx_function", int_sort, int_sort, ctx=pctx.ctx)
    assert constant.ctx == pctx.ctx
    assert function.domain(0).ctx == pctx.ctx
    assert function.range().ctx == pctx.ctx
