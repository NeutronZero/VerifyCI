"""Coverage for the core anomaly checkers.

`z3_prover.prove_function_diff` is the highest-risk module in the engine: it is
what turns a diff into a defect verdict, and it is the least covered. These
tests exercise each anomaly path directly with a base/head pair that isolates
one defect class, so a regression in one checker cannot be masked by another.
"""

from __future__ import annotations

import pytest

from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
from verifyci_v2.neural.spec_compiler import IntentToSMTCompiler
from verifyci_v2.symbolic.z3_prover import Z3SymbolicProver


def _lower(path: str, source: str):
    return {
        f.qualified_name: f
        for f in lower_file_to_ussa(path, source, language="python")
    }


def _prove(base_src: str, head_src: str, path: str = "src/m.py"):
    prover = Z3SymbolicProver(timeout_ms=3000)
    base = _lower(path, base_src)
    head = _lower(path, head_src)
    findings: list = []
    for qname, func_head in head.items():
        func_base = base.get(qname)
        if func_base is None or func_base.h_body == func_head.h_body:
            continue
        findings.extend(
            prover.prove_function_diff(
                file_path=path,
                base_source=base_src,
                head_source=head_src,
                func_base=func_base,
                func_head=func_head,
            )
        )
    return findings


def _rules(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --- cap004: argument and return swaps ------------------------------------


def test_call_argument_swap_is_proven() -> None:
    findings = _prove(
        "def call_fn(a: int, b: int) -> int:\n    return wire(a, b)\n",
        "def call_fn(a: int, b: int) -> int:\n    return wire(b, a)\n",
    )
    assert "VC2-CAP004-CALL-SWAP" in _rules(findings)
    finding = next(f for f in findings if f.rule_id == "VC2-CAP004-CALL-SWAP")
    assert finding.verdict == "FAIL"
    assert finding.witness is not None
    assert finding.witness.smt_status == "SAT"


def test_return_value_swap_is_detected() -> None:
    findings = _prove(
        "def choose(x: int) -> int:\n    if x > 0:\n        return 1\n    return 2\n",
        "def choose(x: int) -> int:\n    if x > 0:\n        return 2\n    return 1\n",
    )
    assert _rules(findings), "swapped returns produced no finding"


def test_guard_inversion_is_detected() -> None:
    findings = _prove(
        "def allow(role: int) -> bool:\n    if role >= 1:\n        return True\n    return False\n",
        "def allow(role: int) -> bool:\n    if role < 1:\n        return True\n    return False\n",
    )
    assert "VC2-CAP002-GUARD-INVERSION" in _rules(findings)


def test_shadow_assignment_is_detected() -> None:
    """The rule targets shadowing a *parameter*, not a local binding."""
    findings = _prove(
        "def compute(x: int, scale: int) -> int:\n    return x * scale\n",
        "def compute(x: int, scale: int) -> int:\n    scale = 5\n    return x * scale\n",
    )
    assert _rules(findings), "parameter shadow assignment produced no finding"


# --- escalation and equivalence ------------------------------------------


def test_unsupported_construct_escalates_to_inconclusive() -> None:
    findings = _prove(
        "def total(xs: list) -> int:\n    acc = 0\n    return acc\n",
        "def total(xs: list) -> int:\n    acc = 0\n    for v in xs:\n        acc += v\n    return acc\n",
    )
    assert any(
        f.rule_id == "VC2-Z3-UNSUPPORTED-AST" and f.verdict == "INCONCLUSIVE"
        for f in findings
    ), [f.rule_id for f in findings]


def test_arithmetic_divergence_is_proven_not_assumed() -> None:
    prover = Z3SymbolicProver(timeout_ms=3000)
    base_src = "def add_one(x: int) -> int:\n    return x + 1\n"
    head_src = "def add_one(x: int) -> int:\n    return x + 2\n"
    base = _lower("src/m.py", base_src)
    head = _lower("src/m.py", head_src)
    name = next(iter(base))
    is_eq, status = prover.prove_equivalence(
        base_source=base_src,
        cand_source=head_src,
        func_base=base[name],
        func_cand=head[name],
    )
    assert is_eq is False
    assert status == "SAT"


def test_refactoring_that_is_equivalent_proves_unsat() -> None:
    """A behaviour-preserving rewrite must not be reported as divergence."""
    prover = Z3SymbolicProver(timeout_ms=3000)
    base_src = "def add_one(x: int) -> int:\n    return x + 1\n"
    head_src = "def add_one(x: int) -> int:\n    return 1 + x\n"
    base = _lower("src/m.py", base_src)
    head = _lower("src/m.py", head_src)
    name = next(iter(base))
    is_eq, status = prover.prove_equivalence(
        base_source=base_src,
        cand_source=head_src,
        func_base=base[name],
        func_cand=head[name],
    )
    assert is_eq is True
    assert status == "UNSAT"


def test_positional_to_keyword_rebinding_is_not_proven_equivalent() -> None:
    """Changing a call from positional to keyword binding is a semantic change.

    The call normalizer used to discard the keyword name, so `f(a, x)` and
    `f(a, endpoint=x)` normalised identically and the prover reported them
    equivalent on a rebinding it never actually checked.
    """
    prover = Z3SymbolicProver(timeout_ms=3000)
    base_src = "def route(rule):\n    return add_url_rule(rule, 'e')\n"
    head_src = "def route(rule):\n    return add_url_rule(rule, endpoint='e')\n"
    base = _lower("src/m.py", base_src)
    head = _lower("src/m.py", head_src)
    name = next(iter(base))
    is_eq, status = prover.prove_equivalence(
        base_source=base_src,
        cand_source=head_src,
        func_base=base[name],
        func_cand=head[name],
    )
    assert is_eq is False, "a positional/keyword rebinding was reported equivalent"
    assert status != "UNSAT"


def test_identical_keyword_binding_on_both_sides_still_proves_unsat() -> None:
    """The keyword guard must not reject a genuinely unchanged keyword call."""
    prover = Z3SymbolicProver(timeout_ms=3000)
    src = "def route(rule, ep):\n    return add_url_rule(rule, endpoint=ep)\n"
    base = _lower("src/m.py", src)
    head = _lower("src/m.py", src)
    name = next(iter(base))
    is_eq, status = prover.prove_equivalence(
        base_source=src,
        cand_source=src,
        func_base=base[name],
        func_cand=head[name],
    )
    assert is_eq is True
    assert status == "UNSAT"


def test_empty_structural_signature_never_claims_equivalence() -> None:
    """No captured effect means no evidence, so the engine must abstain.

    When a function body produced no RETURN/CALL/BRANCH effect the signature
    was empty and its digest matched for *any* two bodies, so unrelated
    functions were reported as equivalent.
    """
    from verifyci_v2.symbolic.egglog_engine import EgglogEquivalenceEngine

    base_src = "def a(ctx):\n    formatter = ctx.make_formatter()\n"
    head_src = "def a(ctx):\n    formatter = ctx.make_formatter(prog_name=ctx.name)\n"
    base = _lower("src/m.py", base_src)
    head = _lower("src/m.py", head_src)
    name = next(iter(base))
    result = EgglogEquivalenceEngine().check_equivalence(base[name], head[name])
    assert result.is_equivalent is False
    assert result.verdict == "INCONCLUSIVE"


# --- intent compiler ------------------------------------------------------


def test_intent_compiler_matches_only_declared_patterns() -> None:
    """Documents the real coverage: three numeric patterns, nothing else.

    Authorization prose has no compiled form, which is why an intent like
    "must deny non-admin users" yields no postcondition at all.
    """
    compiler = IntentToSMTCompiler()
    assert compiler.compile_intent("result must be non-negative") is not None
    assert compiler.compile_intent("result must be positive") is not None
    assert compiler.compile_intent("must never exceed 100") is not None
    assert (
        compiler.compile_intent("authorization must deny non-admin users") is None
    )


@pytest.mark.parametrize(
    "intent",
    ["result must be non-negative", "result must be positive", "must never exceed 42"],
)
def test_compiled_intent_is_smt_expressible(intent: str) -> None:
    spec = IntentToSMTCompiler().compile_intent(intent)
    assert spec is not None
    assert spec.smt_lib_expr.startswith("(assert")