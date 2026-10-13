"""Tests for benchmark provenance tracking and git tree cleanliness enforcement.

Verifies that get_git_provenance() across CAP-009 through CAP-013:
- Parses porcelain -z correctly.
- Prevents staged-rename bypasses where production code is renamed to a whitelisted artifact name.
- Fails closed on untracked or modified non-exempt code.
- Accepts legitimate whitelisted artifact updates.
- Fails closed if git commit is unknown or subprocess calls fail.
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

HARNESS_PATHS = [
    REPO_ROOT / "benchmarks" / "diff_impact_corpus" / "cap009" / "measure_cap009.py",
    REPO_ROOT / "benchmarks" / "retrieval_generalization" / "cap010" / "measure_cap010.py",
    REPO_ROOT / "benchmarks" / "secret_heldout" / "cap011" / "measure_cap011.py",
    REPO_ROOT / "benchmarks" / "repo_perf" / "cap012" / "measure_cap012.py",
    REPO_ROOT / "benchmarks" / "robustness" / "cap013" / "measure_cap013.py",
]


def _load_harness_provenance_fn(harness_path: Path) -> Callable[[], tuple[str, bool]]:
    spec = importlib.util.spec_from_file_location(harness_path.stem, harness_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, "get_git_provenance")


@pytest.fixture(params=HARNESS_PATHS, ids=lambda p: p.parent.name)
def harness_provenance(request):
    return _load_harness_provenance_fn(request.param)


def test_provenance_clean_tree(monkeypatch, harness_provenance):
    def fake_check_output(cmd, **kwargs):
        if cmd == ["git", "rev-parse", "HEAD"]:
            return "0123456789abcdef0123456789abcdef01234567\n"
        if cmd == ["git", "status", "--porcelain", "-z"]:
            return b""
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    commit, dirty = harness_provenance()
    assert commit == "0123456789abcdef0123456789abcdef01234567"
    assert dirty is False


def test_provenance_allowed_exempt_artifacts(monkeypatch, harness_provenance):
    allowed_payload = (
        b" M benchmarks/diff_impact_corpus/cap009/results.json\x00"
        b" M benchmarks/retrieval_generalization/cap010/RESULTS.md\x00"
        b"?? benchmark-results-ubuntu-latest.json\x00"
        b"?? benchmark-results-windows-latest.json\x00"
        b" M evidence/cap-adjudication-bundle.json\x00"
    )

    def fake_check_output(cmd, **kwargs):
        if cmd == ["git", "rev-parse", "HEAD"]:
            return "abc1234\n"
        if cmd == ["git", "status", "--porcelain", "-z"]:
            return allowed_payload
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    commit, dirty = harness_provenance()
    assert dirty is False


def test_provenance_detects_modified_code(monkeypatch, harness_provenance):
    dirty_payload = (
        b" M verifyci/core.py\x00"
        b"?? benchmark-results-ubuntu-latest.json\x00"
    )

    def fake_check_output(cmd, **kwargs):
        if cmd == ["git", "rev-parse", "HEAD"]:
            return "abc1234\n"
        if cmd == ["git", "status", "--porcelain", "-z"]:
            return dirty_payload
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    _, dirty = harness_provenance()
    assert dirty is True


def test_provenance_detects_untracked_code(monkeypatch, harness_provenance):
    dirty_payload = b"?? verifyci/evil.py\x00"

    def fake_check_output(cmd, **kwargs):
        if cmd == ["git", "rev-parse", "HEAD"]:
            return "abc1234\n"
        if cmd == ["git", "status", "--porcelain", "-z"]:
            return dirty_payload
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    _, dirty = harness_provenance()
    assert dirty is True


def test_provenance_detects_staged_rename_bypass_src(monkeypatch, harness_provenance):
    # Staged rename of production source file to exempt path
    # In porcelain -z, status is R, tokens are R  <new_path>\x00<old_path>\x00
    dirty_payload = b"R  benchmark-results-linux.json\x00verifyci/module.py\x00"

    def fake_check_output(cmd, **kwargs):
        if cmd == ["git", "rev-parse", "HEAD"]:
            return "abc1234\n"
        if cmd == ["git", "status", "--porcelain", "-z"]:
            return dirty_payload
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    _, dirty = harness_provenance()
    assert dirty is True


def test_provenance_detects_staged_rename_bypass_dst(monkeypatch, harness_provenance):
    # Staged rename of exempt path to production source file
    dirty_payload = b"R  verifyci/module.py\x00benchmark-results-linux.json\x00"

    def fake_check_output(cmd, **kwargs):
        if cmd == ["git", "rev-parse", "HEAD"]:
            return "abc1234\n"
        if cmd == ["git", "status", "--porcelain", "-z"]:
            return dirty_payload
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    _, dirty = harness_provenance()
    assert dirty is True


def test_provenance_fails_on_unknown_commit(monkeypatch, harness_provenance):
    def fake_check_output(cmd, **kwargs):
        if cmd == ["git", "rev-parse", "HEAD"]:
            return "unknown\n"
        return b""

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    with pytest.raises(RuntimeError, match="Git commit provenance is invalid or unknown"):
        harness_provenance()


def test_provenance_fails_on_git_failure(monkeypatch, harness_provenance):
    def fake_check_output(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    with pytest.raises(RuntimeError):
        harness_provenance()
