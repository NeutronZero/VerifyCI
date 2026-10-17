"""Tests for lazy Egglog equality saturation adapter."""

from __future__ import annotations

import subprocess
import sys

from verifyci.extensions.egglog_adapter import EgglogRewriterAdapter
from verifyci.extensions.protocols import EGraphStatus


def test_egglog_adapter_lazy_loading() -> None:
    """Verify that importing EgglogRewriterAdapter does not import egglog."""
    code = (
        "import sys\n"
        "from verifyci.extensions.egglog_adapter import EgglogRewriterAdapter\n"
        "assert 'egglog' not in sys.modules, 'egglog eagerly imported!'\n"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_egglog_rewriter_identical_expressions() -> None:
    adapter = EgglogRewriterAdapter()
    res = adapter.check_algebraic_equivalence("x + 1", "x + 1")
    assert res.status == EGraphStatus.EQUIVALENT_UNDER_RULES


def test_egglog_rewriter_saturation_run() -> None:
    adapter = EgglogRewriterAdapter()
    res = adapter.check_algebraic_equivalence("(Add a b)", "(Add b a)")
    assert res.status in (EGraphStatus.REWRITE_SATURATED, EGraphStatus.EQUIVALENT_UNDER_RULES)
