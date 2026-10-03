"""Unit tests for Contract 2: Invariant Applicability & Scope Governance (C2).

Validates the frozen C2 contract from v1_1_scope_specification.md:
- Target scope definitions: code_core, code_and_config, global_strict
- Omitted target_scope defaults fail-closed to global_strict
- test_allowlist_patterns is valid ONLY for global_strict
- Configuration validator rejects test_allowlist_patterns on code_core / code_and_config
- Invariant evaluation applies only to authorized PartitionedDiff partitions
- Tests, documentation, and ancillary files excluded by scope do NOT trigger the rule
- global_strict with test_allowlist_patterns allows synthetic test tokens while failing on production code
"""
import pytest
import tempfile
from pathlib import Path

from verifyci.contracts.verification_ir import Invariant
from verifyci.verification.config import _load_file
from verifyci.verification.intent_align import evaluate_invariants


class TestInvariantConfigScoping:
    """Tests for invariant configuration schema, parsing, and validation."""

    def test_default_target_scope_omitted(self):
        """Omitted target_scope MUST default to global_strict."""
        content = """
invariants:
  - id: no-eval
    rule: forbid eval
    query: forbid_call:eval
    blocking: true
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(content)
            path = tf.name

        try:
            invs = _load_file(path)
            assert len(invs) == 1
            assert invs[0].target_scope == "global_strict"
            assert invs[0].test_allowlist_patterns == ()
        finally:
            Path(path).unlink(missing_ok=True)

    def test_valid_target_scopes(self):
        """All three frozen scopes parse cleanly."""
        content = """
invariants:
  - id: rule-core
    query: forbid_call:eval
    target_scope: code_core
  - id: rule-config
    query: forbid_import:subprocess
    target_scope: code_and_config
  - id: rule-global
    query: secrets_scan
    target_scope: global_strict
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(content)
            path = tf.name

        try:
            invs = _load_file(path)
            assert [inv.target_scope for inv in invs] == [
                "code_core", "code_and_config", "global_strict"
            ]
        finally:
            Path(path).unlink(missing_ok=True)

    def test_invalid_target_scope_rejected(self):
        """Unknown target_scope raises ValueError (fail-closed)."""
        content = """
invariants:
  - id: bad-rule
    query: forbid_call:eval
    target_scope: arbitrary_scope
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(content)
            path = tf.name

        try:
            with pytest.raises(ValueError, match="invalid target_scope"):
                _load_file(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_allowlist_valid_on_global_strict(self):
        """test_allowlist_patterns is allowed when target_scope is global_strict."""
        content = """
invariants:
  - id: sec-rule
    query: secrets_scan
    target_scope: global_strict
    test_allowlist_patterns:
      - "^test_mock_"
      - "AKIAIOSFODNN7EXAMPLE"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(content)
            path = tf.name

        try:
            invs = _load_file(path)
            assert invs[0].target_scope == "global_strict"
            assert invs[0].test_allowlist_patterns == ("^test_mock_", "AKIAIOSFODNN7EXAMPLE")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_allowlist_rejected_on_code_core(self):
        """Validator MUST reject test_allowlist_patterns on code_core."""
        content = """
invariants:
  - id: bad-rule
    query: forbid_call:eval
    target_scope: code_core
    test_allowlist_patterns:
      - "^mock_"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(content)
            path = tf.name

        try:
            with pytest.raises(ValueError, match="test_allowlist_patterns is only valid for target_scope 'global_strict'"):
                _load_file(path)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_allowlist_rejected_on_code_and_config(self):
        """Validator MUST reject test_allowlist_patterns on code_and_config."""
        content = """
invariants:
  - id: bad-rule
    query: forbid_call:eval
    target_scope: code_and_config
    test_allowlist_patterns:
      - "^mock_"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(content)
            path = tf.name

        try:
            with pytest.raises(ValueError, match="test_allowlist_patterns is only valid for target_scope 'global_strict'"):
                _load_file(path)
        finally:
            Path(path).unlink(missing_ok=True)


class TestInvariantScopeEvaluation:
    """Tests for scoped invariant evaluation against multi-partition diffs."""

    DIFF_CORE_AND_TEST = """diff --git a/verifyci/core.py b/verifyci/core.py
--- a/verifyci/core.py
+++ b/verifyci/core.py
@@ -1,2 +1,3 @@
 def run():
+    x = 1
     return True
diff --git a/tests/test_core.py b/tests/test_core.py
--- a/tests/test_core.py
+++ b/tests/test_core.py
@@ -10,2 +10,3 @@
 def test_eval():
+    eval("2+2")
     pass
"""

    DIFF_CORE_VIOLATION = """diff --git a/verifyci/core.py b/verifyci/core.py
--- a/verifyci/core.py
+++ b/verifyci/core.py
@@ -1,2 +1,3 @@
 def run():
+    eval("1+1")
     return True
diff --git a/tests/test_core.py b/tests/test_core.py
--- a/tests/test_core.py
+++ b/tests/test_core.py
@@ -10,2 +10,3 @@
 def test_clean():
+    pass
"""

    def test_scope_code_core_ignores_test_violations(self):
        """code_core scope ignores eval in tests/test_core.py."""
        rule_core = Invariant(
            invariant_id="no-eval",
            rule="forbid eval",
            compiled_query="forbid_call:eval",
            blocking=True,
            target_scope="code_core",
        )
        results, _ = evaluate_invariants(self.DIFF_CORE_AND_TEST, [rule_core])
        assert len(results) == 1
        assert results[0].passed is True  # Ignored test file, no violation in core

    def test_scope_global_strict_catches_test_violations(self):
        """global_strict scope catches eval in tests/test_core.py."""
        rule_global = Invariant(
            invariant_id="no-eval",
            rule="forbid eval",
            compiled_query="forbid_call:eval",
            blocking=True,
            target_scope="global_strict",
        )
        results, _ = evaluate_invariants(self.DIFF_CORE_AND_TEST, [rule_global])
        assert len(results) == 1
        assert results[0].passed is False  # Flags eval in tests/
        assert "tests/test_core.py" in results[0].explanation

    def test_scope_code_core_catches_production_violations(self):
        """code_core scope still catches eval in verifyci/core.py."""
        rule_core = Invariant(
            invariant_id="no-eval",
            rule="forbid eval",
            compiled_query="forbid_call:eval",
            blocking=True,
            target_scope="code_core",
        )
        results, _ = evaluate_invariants(self.DIFF_CORE_VIOLATION, [rule_core])
        assert len(results) == 1
        assert results[0].passed is False
        assert "verifyci/core.py" in results[0].explanation

    def test_scope_code_and_config(self):
        """code_and_config scans core and config, ignoring test suite."""
        diff = """diff --git a/pyproject.toml b/pyproject.toml
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -1,2 +1,3 @@
 [project]
+import_probe = "subprocess"
diff --git a/tests/test_config.py b/tests/test_config.py
--- a/tests/test_config.py
+++ b/tests/test_config.py
@@ -1,2 +1,3 @@
+import subprocess
"""
        rule = Invariant(
            invariant_id="no-subprocess",
            rule="forbid subprocess",
            compiled_query="forbid_import:subprocess",
            blocking=True,
            target_scope="code_and_config",
        )
        results, _ = evaluate_invariants(diff, [rule])
        # In tests/, subprocess is imported, but tests/ is excluded under code_and_config
        # In pyproject.toml, it's not a python import, so no import hit
        assert len(results) == 1
        assert results[0].passed is True

    def test_global_strict_allowlist_filtering(self):
        """test_allowlist_patterns filters synthetic test tokens in TEST_SUITE."""
        test_secret_diff = """diff --git a/tests/test_auth.py b/tests/test_auth.py
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,2 +1,3 @@
 def test_mock_key():
+    token = "AKIAIOSFODNN7EXAMPLE"
"""
        # Without allowlist -> fails
        rule_no_allow = Invariant(
            invariant_id="sec",
            rule="no secrets",
            compiled_query="secrets_scan",
            blocking=True,
            target_scope="global_strict",
        )
        res_no_allow, _ = evaluate_invariants(test_secret_diff, [rule_no_allow])
        assert res_no_allow[0].passed is False

        # With allowlist -> passes in tests
        rule_with_allow = Invariant(
            invariant_id="sec",
            rule="no secrets",
            compiled_query="secrets_scan",
            blocking=True,
            target_scope="global_strict",
            test_allowlist_patterns=("AKIAIOSFODNN7EXAMPLE",),
        )
        res_with_allow, _ = evaluate_invariants(test_secret_diff, [rule_with_allow])
        assert res_with_allow[0].passed is True

    def test_global_strict_allowlist_does_not_protect_production_code(self):
        """test_allowlist_patterns NEVER protects production code in CODE_CORE."""
        core_secret_diff = """diff --git a/verifyci/auth.py b/verifyci/auth.py
--- a/verifyci/auth.py
+++ b/verifyci/auth.py
@@ -1,2 +1,3 @@
 def login():
+    token = "AKIAIOSFODNN7EXAMPLE"
"""
        rule = Invariant(
            invariant_id="sec",
            rule="no secrets",
            compiled_query="secrets_scan",
            blocking=True,
            target_scope="global_strict",
            test_allowlist_patterns=("AKIAIOSFODNN7EXAMPLE",),
        )
        results, _ = evaluate_invariants(core_secret_diff, [rule])
        # Even with allowlist, production code violation MUST fail
        assert results[0].passed is False
        assert "verifyci/auth.py" in results[0].explanation
