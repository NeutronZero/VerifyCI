"""Unit and adversarial tests for the lazy Z3ProverAdapter."""

from __future__ import annotations

import subprocess
import sys

from verifyci.contracts.verdict import FindingReason, VerificationVerdict
from verifyci.extensions.protocols import EquivalenceStatus
from verifyci.extensions.z3_adapter import Z3ProverAdapter


def test_z3_adapter_lazy_loading() -> None:
    """Verify that importing Z3ProverAdapter does not import z3."""
    code = (
        "import sys\n"
        "from verifyci.extensions.z3_adapter import Z3ProverAdapter\n"
        "assert 'z3' not in sys.modules, 'z3 eagerly imported!'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_z3_proves_algebraic_commutativity() -> None:
    base_src = "def add(a: int, b: int) -> int:\n    return a + b\n"
    head_src = "def add(a: int, b: int) -> int:\n    return b + a\n"

    adapter = Z3ProverAdapter()
    results = adapter.prove_function_diff("src/calc.py", base_src, head_src)

    assert len(results) == 1
    res = results[0]
    assert res.status == EquivalenceStatus.PROVEN_EQUIVALENT
    assert len(res.findings) == 0


def test_z3_proves_semantic_divergence_with_counterexample() -> None:
    base_src = "def calc(a: int, b: int) -> int:\n    return a + b\n"
    head_src = "def calc(a: int, b: int) -> int:\n    return a - b\n"

    adapter = Z3ProverAdapter()
    results = adapter.prove_function_diff("src/calc.py", base_src, head_src)

    assert len(results) == 1
    res = results[0]
    assert res.status == EquivalenceStatus.PROVEN_DIVERGENT
    assert len(res.counterexamples) > 0
    assert len(res.findings) == 1

    finding = res.findings[0]
    assert finding.verdict == VerificationVerdict.FAIL
    assert finding.reason == FindingReason.SEMANTIC_DIVERGENCE


def test_z3_unknown_fails_closed_to_inconclusive() -> None:
    base_src = "def loop_fn(items):\n    res = []\n    for x in items:\n        res.append(x)\n    return res\n"
    head_src = "def loop_fn(items):\n    return list(items)\n"

    adapter = Z3ProverAdapter()
    results = adapter.prove_function_diff("src/loop.py", base_src, head_src)

    assert len(results) == 1
    res = results[0]
    assert res.status == EquivalenceStatus.UNKNOWN
    assert len(res.findings) == 1
    assert res.findings[0].verdict == VerificationVerdict.INCONCLUSIVE
