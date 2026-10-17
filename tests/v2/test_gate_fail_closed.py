"""Fail-closed gate regression tests (remediation #1B, #1A).

Every assertion here is about a path that must NOT return PASS: an undecidable
or unrunnable check is INCONCLUSIVE, never a green verdict.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import verifyci_v2.symbolic.z3_prover as z3_prover
from verifyci_v2.interface.cli import run_cli
from verifyci_v2.store.duckdb_cpg import DuckDBCPGStore


def test_forged_removal_is_rejected_against_stored_base(tmp_path: Path) -> None:
    """Provenance must come from a stored base revision, not the diff itself."""
    from verifyci_v2.interface.cli import run_cli

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "pay.py").write_text(
        "def pay(x):\n    charge = 10\n    return x\n", encoding="utf-8"
    )
    db = str(tmp_path / "store.vc2")
    ingest = run_cli(["ingest", str(repo), "--db", db])
    assert ingest["recorded_source_files"] == 1

    forged = tmp_path / "forged.diff"
    forged.write_text(
        "diff --git a/src/pay.py b/src/pay.py\n"
        "--- a/src/pay.py\n+++ b/src/pay.py\n"
        "@@ -1,3 +1,2 @@\n def pay(x):\n-    charge = 999\n     return x\n",
        encoding="utf-8",
    )
    result = run_cli(
        ["verify-diff", "--diff-file", str(forged), "--db", db, "--format", "json"]
    )
    assert result["status"] == "FAIL"
    assert any(
        f["rule_id"] == "VC2-CAP003A-FABRICATED-REMOVAL" for f in result["findings"]
    )


def test_honest_removal_against_stored_base_passes(tmp_path: Path) -> None:
    from verifyci_v2.interface.cli import run_cli

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "pay.py").write_text(
        "def pay(x):\n    charge = 10\n    return x\n", encoding="utf-8"
    )
    db = str(tmp_path / "store.vc2")
    run_cli(["ingest", str(repo), "--db", db])

    honest = tmp_path / "honest.diff"
    honest.write_text(
        "diff --git a/src/pay.py b/src/pay.py\n"
        "--- a/src/pay.py\n+++ b/src/pay.py\n"
        "@@ -1,3 +1,2 @@\n def pay(x):\n-    charge = 10\n     return x\n",
        encoding="utf-8",
    )
    result = run_cli(
        ["verify-diff", "--diff-file", str(honest), "--db", db, "--format", "json"]
    )
    assert not any(
        f["rule_id"].startswith("VC2-CAP003A") for f in result["findings"]
    ), [f["rule_id"] for f in result["findings"]]


def test_provenance_is_skipped_without_a_stored_base(tmp_path: Path) -> None:
    """No base record means the check cannot run; it must not pretend to."""
    from verifyci_v2.interface.cli import run_cli

    diff_file = tmp_path / "d.diff"
    diff_file.write_text(ARITHMETIC_DIVERGENCE_DIFF, encoding="utf-8")
    result = run_cli(["verify-diff", "--diff-file", str(diff_file), "--format", "json"])
    assert not any(
        f["rule_id"].startswith("VC2-CAP003A") for f in result["findings"]
    )




ARITHMETIC_DIVERGENCE_DIFF = """diff --git a/m.py b/m.py
--- a/m.py
+++ b/m.py
@@ -1,2 +1,2 @@
 def add_one(x: int) -> int:
-    return x + 1
+    return x + 2
"""


def _write_diff(tmp_path: Path, text: str) -> str:
    diff_file = tmp_path / "case.diff"
    diff_file.write_text(text, encoding="utf-8")
    return str(diff_file)


def test_behavioural_divergence_is_fail_with_solver(tmp_path: Path) -> None:
    diff_file = _write_diff(tmp_path, ARITHMETIC_DIVERGENCE_DIFF)
    result = run_cli(["verify-diff", "--diff-file", diff_file, "--format", "json"])
    assert result["status"] == "FAIL"
    assert any(
        f["rule_id"] == "VC2-Z3-SEMANTIC-DIVERGENCE" for f in result["findings"]
    )


def test_divergence_fails_closed_without_solver(tmp_path: Path) -> None:
    """A body change that cannot be decided must never report PASS."""
    diff_file = _write_diff(tmp_path, ARITHMETIC_DIVERGENCE_DIFF)
    real_z3 = z3_prover._z3_mod
    z3_prover._z3_mod = None
    try:
        result = run_cli(
            ["verify-diff", "--diff-file", diff_file, "--format", "json"]
        )
    finally:
        z3_prover._z3_mod = real_z3

    assert result["status"] != "PASS"
    assert result["status"] == "INCONCLUSIVE"
    assert any(
        f["rule_id"] == "VC2-Z3-SOLVER-UNAVAILABLE" for f in result["findings"]
    )


def test_secret_engine_crash_is_inconclusive_not_pass(tmp_path: Path) -> None:
    """A checker exception must surface, never be swallowed into a PASS."""
    # The pipeline owns engine construction, so it is the module that resolves
    # the name at call time; patching the engine's defining module would leave
    # the already-imported reference untouched.
    import verifyci_v2.pipeline as pipeline_module

    diff_file = _write_diff(tmp_path, ARITHMETIC_DIVERGENCE_DIFF)

    class _ExplodingSecretEngine:
        def scan_python_source(self, *args: object, **kwargs: object) -> tuple:
            raise RuntimeError("engine down")

    real_engine = pipeline_module.TaintTrackedSecretEngine
    pipeline_module.TaintTrackedSecretEngine = _ExplodingSecretEngine  # type: ignore[assignment,misc]
    try:
        result = run_cli(
            ["verify-diff", "--diff-file", diff_file, "--format", "json"]
        )
    finally:
        pipeline_module.TaintTrackedSecretEngine = real_engine  # type: ignore[assignment,misc]

    assert any(
        f["rule_id"] == "VC2-SECRET-ENGINE-ERROR" for f in result["findings"]
    )
    assert result["status"] != "PASS"


def test_ingest_discloses_active_backend(tmp_path: Path) -> None:
    """Silent SQLite fallback must be visible in the ingest result."""
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "pkg" / "m.py").write_text("def f(x: int) -> int:\n    return x + 1\n")

    result = run_cli(["ingest", str(repo), "--db", str(tmp_path / "s.vc2")])
    assert result["status"] in ("ok", "partial_ingest")
    assert result["active_backend"] in ("duckdb", "sqlite")


def test_duckdb_backend_rejects_sqlite_store(tmp_path: Path) -> None:
    """Cross-format stores fail closed instead of erroring deep inside DML."""
    import sqlite3

    store_path = os.path.join(str(tmp_path), "legacy.vc2")
    sqlite3.connect(store_path).execute("CREATE TABLE t(x)")

    with pytest.raises(RuntimeError, match="SQLite database"):
        DuckDBCPGStore(store_path, backend="duckdb")

    # The sqlite backend must still open the same file.
    assert DuckDBCPGStore(store_path, backend="sqlite").active_backend == "sqlite"