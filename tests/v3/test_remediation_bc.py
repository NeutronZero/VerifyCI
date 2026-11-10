"""Phase B/C remediation regression tests (compact)."""

from __future__ import annotations

from verifyci.contracts.release_validation import _CRITICAL_IMPLEMENTATION_FILES
from verifyci.gate.orchestrator import _safe_detail
from verifyci.contracts.release_validation import _scrubbed_git_env


def test_safe_detail_scrubs_paths_and_truncates():
    exc = ValueError("boom at C:\\secret\\path\\file.py and /very/long/absolute/path/here")
    out = _safe_detail(exc)
    assert "ValueError" in out
    assert "<path>" in out
    assert "C:\\secret" not in out
    assert len(out) <= 200


def test_critical_implementation_files_include_core_modules():
    paths = {p.as_posix() for p in _CRITICAL_IMPLEMENTATION_FILES}
    for required in (
        "verifyci/scm/git.py",
        "verifyci/gate/verdict.py",
        "verifyci/contracts/model.py",
        "verifyci/runtime/budget.py",
        "verifyci/checks/base.py",
    ):
        assert required in paths, required


def test_scrubbed_git_env_removes_secrets():
    import os

    os.environ["VERIFYCI_RELEASE_SIGNING_KEY"] = "super_secret"
    env = _scrubbed_git_env()
    assert "VERIFYCI_RELEASE_SIGNING_KEY" not in env
    assert env.get("GIT_TERMINAL_PROMPT") == "0"