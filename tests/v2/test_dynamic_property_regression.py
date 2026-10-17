"""Regression tests for REAL-DYN-04 and dynamic property assignment variants.

Verifies that dynamic property, attribute, and subscript assignments without execution
witnesses fail closed to INCONCLUSIVE and never produce a false PASS.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from verifyci_v2.interface.cli import run_cli


def _verify_diff_text(diff_text: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False, encoding="utf-8") as fh:
        fh.write(diff_text)
        diff_path = fh.name
    try:
        return run_cli(["verify-diff", "--diff-file", diff_path, "--format", "json"])
    finally:
        Path(diff_path).unlink(missing_ok=True)


def test_real_dyn_04_frozen_case_fails_closed() -> None:
    """Exact frozen REAL-DYN-04 case from cap005: must be INCONCLUSIVE, not PASS."""
    diff = (
        "diff --git a/src/flask/app.py b/src/flask/app.py\n"
        "--- a/src/flask/app.py\n"
        "+++ b/src/flask/app.py\n"
        "@@ -45,3 +45,4 @@\n"
        "     def register_converter(self, name, cls):\n"
        "-        pass\n"
        "+        self.url_map.converters[name] = cls\n"
    )
    result = _verify_diff_text(diff)
    assert result["status"] == "INCONCLUSIVE", (
        f"REAL-DYN-04 must fail closed to INCONCLUSIVE; got {result['status']}: {result.get('verdict')}"
    )


def test_adversarial_direct_attribute_assignment_fails_closed() -> None:
    """Direct dynamic attribute write cannot be proven equivalent to pass."""
    diff = (
        "diff --git a/src/flask/app.py b/src/flask/app.py\n"
        "--- a/src/flask/app.py\n"
        "+++ b/src/flask/app.py\n"
        "@@ -45,3 +45,4 @@\n"
        "     def register_converter(self, name, cls):\n"
        "-        pass\n"
        "+        self.converter = cls\n"
    )
    result = _verify_diff_text(diff)
    assert result["status"] == "INCONCLUSIVE"


def test_adversarial_aliased_property_assignment_fails_closed() -> None:
    """Property write through alias/local variable reference must fail closed."""
    diff = (
        "diff --git a/src/flask/app.py b/src/flask/app.py\n"
        "--- a/src/flask/app.py\n"
        "+++ b/src/flask/app.py\n"
        "@@ -45,3 +45,5 @@\n"
        "     def register_converter(self, name, cls):\n"
        "-        pass\n"
        "+        m = self.url_map\n"
        "+        m.converters[name] = cls\n"
    )
    result = _verify_diff_text(diff)
    assert result["status"] == "INCONCLUSIVE"


def test_adversarial_indirect_setattr_fails_closed() -> None:
    """Indirect property assignment via setattr builtin must fail closed."""
    diff = (
        "diff --git a/src/flask/app.py b/src/flask/app.py\n"
        "--- a/src/flask/app.py\n"
        "+++ b/src/flask/app.py\n"
        "@@ -45,3 +45,4 @@\n"
        "     def register_converter(self, name, cls):\n"
        "-        pass\n"
        "+        setattr(self, name, cls)\n"
    )
    result = _verify_diff_text(diff)
    assert result["status"] == "INCONCLUSIVE"
