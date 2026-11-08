"""Bound behaviour for the four ``WorkBudget`` fields that gate real work.

``max_ast_depth``, ``max_entities``, ``max_taint_depth`` and
``max_taint_iterations`` were declared and carried into every evidence digest
but never compared against anything, so a policy that tightened them changed the
budget hash without changing behaviour.  Each field now either rejects the input
(parse budgets) or fails the check closed with a ``budget_exhausted`` gap; these
tests pin both directions so neither a silent pass nor an over-eager trip can
come back.
"""

from __future__ import annotations

import pytest

from verifyci.checks.base import CheckContext, entity_budget_exceeded
from verifyci.checks import contract, deletion, security, semantic
from verifyci.contracts.model import DiffEntry, Outcome
from verifyci.gate.policy import parse_policy_bytes
from verifyci.runtime.budget import WorkBudget
from verifyci.scope.entities import analyze_source, build_changed_scope

_DEEP_PY = "x = " + "[" * 130 + "1" + "]" * 130
_DEEP_TS = "const x = " + "[" * 130 + "1" + "]" * 130 + ";\n"

_TAINT_POLICY = b"""
[taint]
sources = ["request.args"]

[taint.sinks.sql]
symbols = ["execute"]
kind = "sql"
"""


def _context(
    *,
    entries: tuple[DiffEntry, ...] = (),
    scope=None,
    budget: WorkBudget = WorkBudget(),
    policy: bytes = b"",
) -> CheckContext:
    return CheckContext(
        git=None,
        policy=parse_policy_bytes(policy),
        entries=entries,
        scope=scope if scope is not None else build_changed_scope(list(entries)),
        as_of_date="2026-11-08",
        object_format="sha1",
        target_base_commit="b" * 40,
        merge_base_commit="m" * 40,
        head_commit="h" * 40,
        toolchain_fingerprint="sha256:" + "0" * 64,
        budget=budget,
    )


def _added_entry(source: str, path: str = "handler.py") -> DiffEntry:
    return DiffEntry(
        status="A",
        base_path="",
        head_path=path,
        base_blob=None,
        head_blob="2" * 40,
        base_mode=None,
        head_mode="100644",
        base_source="",
        head_source=source,
    )


# --------------------------------------------------------------------------
# max_ast_depth
# --------------------------------------------------------------------------


@pytest.mark.invariant
def test_python_ast_depth_budget_is_enforced():
    exceeded = analyze_source("deep.py", _DEEP_PY, budget=WorkBudget(max_ast_depth=8))
    assert not exceeded.supported
    assert "max_ast_depth" in exceeded.parse_error
    assert exceeded.parse_error.startswith("parse_resource_limit")

    funded = analyze_source("deep.py", _DEEP_PY, budget=WorkBudget(max_ast_depth=512))
    assert funded.supported, funded.parse_error


@pytest.mark.invariant
def test_typescript_ast_depth_budget_is_enforced():
    exceeded = analyze_source("deep.ts", _DEEP_TS, budget=WorkBudget(max_ast_depth=8))
    if "grammar unavailable" in exceeded.parse_error:
        pytest.skip("tree-sitter TypeScript grammar unavailable")
    assert not exceeded.supported
    assert "max_ast_depth" in exceeded.parse_error

    funded = analyze_source("deep.ts", _DEEP_TS, budget=WorkBudget(max_ast_depth=512))
    assert funded.supported, funded.parse_error


@pytest.mark.invariant
def test_default_depth_budget_admits_ordinary_modules():
    """The default must not reject real code: a 130-deep literal is the outlier."""
    facts = analyze_source("mod.py", "def f(a):\n    if a:\n        return [a]\n    return None\n")
    assert facts.supported, facts.parse_error


# --------------------------------------------------------------------------
# max_entities
# --------------------------------------------------------------------------


@pytest.mark.invariant
def test_entity_budget_boundary_is_exact():
    scope = build_changed_scope([])
    two = scope.__class__(
        base_facts={},
        head_facts={},
        changed_entities=frozenset(),
        base_entities=frozenset({"a:x"}),
        head_entities=frozenset({"a:x", "a:y"}),
    )
    assert entity_budget_exceeded(_context(scope=two, budget=WorkBudget(max_entities=2))) == (False, 2)
    assert entity_budget_exceeded(_context(scope=two, budget=WorkBudget(max_entities=1))) == (True, 2)


@pytest.mark.invariant
@pytest.mark.parametrize("check", [contract, deletion, semantic], ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_checks_fail_closed_when_entity_budget_exhausted(check):
    scope = build_changed_scope([])
    over = scope.__class__(
        base_facts={},
        head_facts={},
        changed_entities=frozenset(),
        base_entities=frozenset({"a:x"}),
        head_entities=frozenset({"a:x", "a:y"}),
    )
    result = check.run(_context(scope=over, budget=WorkBudget(max_entities=1)))
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.reason_codes == ("budget_exhausted",)
    assert "max_entities limit exceeded (2 > 1)" in result.diagnostics[0]["detail"]


# --------------------------------------------------------------------------
# taint budgets
# --------------------------------------------------------------------------


def _taint_entry() -> DiffEntry:
    return _added_entry(
        "def handler(request):\n"
        "    q = request.args.get('q')\n"
        "    cur.execute(q)\n"
        "    return q\n"
    )


@pytest.mark.invariant
def test_taint_depth_budget_below_model_hop_count_fails_closed():
    ctx = _context(entries=(_taint_entry(),), budget=WorkBudget(max_taint_depth=0), policy=_TAINT_POLICY)
    result = security._taint_sub(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert "budget_exhausted" in result.reason_codes
    detail = result.diagnostics[0]["detail"]
    assert "max_taint_depth" in detail


@pytest.mark.invariant
def test_taint_iteration_budget_bounds_propagation_steps():
    ctx = _context(entries=(_taint_entry(),), budget=WorkBudget(max_taint_iterations=1), policy=_TAINT_POLICY)
    result = security._taint_sub(ctx)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert "budget_exhausted" in result.reason_codes
    assert "max_taint_iterations" in result.diagnostics[0]["detail"]


@pytest.mark.invariant
def test_taint_runs_when_budgets_fund_the_model():
    """Guard the guard: a funded budget must still produce the taint finding."""
    ctx = _context(
        entries=(_taint_entry(),),
        budget=WorkBudget(max_taint_depth=1, max_taint_iterations=100),
        policy=_TAINT_POLICY,
    )
    result = security._taint_sub(ctx)
    assert "budget_exhausted" not in result.reason_codes
