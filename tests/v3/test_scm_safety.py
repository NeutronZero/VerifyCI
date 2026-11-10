"""Tests for SCM diff parsing, subprocess credential scrubbing, and path safety."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from scripts.ci_test_selector import FULL_RUN_TRIGGERS, get_changed_files, select_tests
from verifyci.contracts.names import is_safe_repo_path, normalize_repo_path
from verifyci.scm.git import GitRepo, _parse_patch_hunks, _patch_path


def test_patch_path_preserves_genuine_directories():
    # Calling without prefix should preserve genuine directory prefixes 'a/' and 'b/'
    assert _patch_path("a/real_dir/file.py") == "a/real_dir/file.py"
    assert _patch_path("b/sub/mod.ts") == "b/sub/mod.ts"

    # Stripping diff header prefix 'a/' or 'b/' explicitly
    assert _patch_path("a/a/real_dir/file.py", prefix="a/") == "a/real_dir/file.py"
    assert _patch_path("b/b/sub/mod.ts", prefix="b/") == "b/sub/mod.ts"
    assert _patch_path("a/b/sub/mod.ts", prefix="a/") == "b/sub/mod.ts"
    assert _patch_path("b/a/real_dir/file.py", prefix="b/") == "a/real_dir/file.py"

    # Diff /dev/null handling
    assert _patch_path("/dev/null") == ""
    assert _patch_path("/dev/null", prefix="a/") == ""
    assert _patch_path("/dev/null", prefix="b/") == ""

    # Parsing full patch hunks with 'a/' and 'b/' genuine directory paths
    patch_bytes = (
        b"diff --git a/a/real_dir/file.py b/a/real_dir/file.py\n"
        b"--- a/a/real_dir/file.py\n"
        b"+++ b/a/real_dir/file.py\n"
        b"@@ -1,3 +1,4 @@\n"
        b" context\n"
    )
    hunks, _warnings = _parse_patch_hunks(patch_bytes)
    assert "a/real_dir/file.py" in hunks
    assert len(hunks["a/real_dir/file.py"]) == 1
    assert hunks["a/real_dir/file.py"][0].new_start == 1


def test_git_repo_scrubs_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("VERIFYCI_RELEASE_SIGNING_KEY", "super_secret_signing_key")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secrettoken123")
    monkeypatch.setenv("GH_TOKEN", "ghp_secrettoken456")
    monkeypatch.setenv("CI_JOB_TOKEN", "job_secret_789")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws_secret")
    monkeypatch.setenv("SAFE_ENV_VAR", "harmless_value")

    repo = GitRepo(tmp_path)
    assert "VERIFYCI_RELEASE_SIGNING_KEY" not in repo.env
    assert "GITHUB_TOKEN" not in repo.env
    assert "GH_TOKEN" not in repo.env
    assert "CI_JOB_TOKEN" not in repo.env
    assert "AWS_SECRET_ACCESS_KEY" not in repo.env
    assert repo.env.get("SAFE_ENV_VAR") == "harmless_value"
    assert repo.env.get("GIT_TERMINAL_PROMPT") == "0"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("foo.", False),
        ("foo ", False),
        ("~", False),
        ("a/foo.", False),
        ("a/foo /b", False),
        ("a/~/b", False),
        ("safe/path.py", True),
        ("a/b/c.ts", True),
    ],
)
def test_is_safe_repo_path_rejects_quirks(path: str, expected: bool):
    assert is_safe_repo_path(path) is expected


def test_normalize_repo_path_collapses_multiple_slashes():
    assert normalize_repo_path("a//b/c") == "a/b/c"
    assert normalize_repo_path("a///b////c") == "a/b/c"
    assert normalize_repo_path(".//a//b") == "a/b"
    assert normalize_repo_path("foo\\\\bar//baz") == "foo/bar/baz"


def test_ci_test_selector_triggers_and_spaces():
    assert "uv.lock" in FULL_RUN_TRIGGERS
    assert "corpora/" in FULL_RUN_TRIGGERS
    assert "verifyci_release_trust/" in FULL_RUN_TRIGGERS

    # FULL_RUN_TRIGGERS trigger full tests run
    assert select_tests(["uv.lock"]) == ["tests/"]
    assert select_tests(["corpora/grounding/manifest.json"]) == ["tests/"]
    assert select_tests(["verifyci_release_trust/signing_key.pub"]) == ["tests/"]

    # Space preservation in paths from git output
    sample_git_diff_stdout = (
        "path with spaces/module.py\n"
        "tests/v3/test with spaces.py\n"
        "verifyci/scm/git.py\n"
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = sample_git_diff_stdout
        changed = get_changed_files("origin/main")
        assert changed == [
            "path with spaces/module.py",
            "tests/v3/test with spaces.py",
            "verifyci/scm/git.py",
        ]
        # Ensure 'path with spaces/module.py' was not truncated
        assert "path with spaces/module.py" in changed

    # Prevent fallback to HEAD~1 or git status when comparing against a base ref
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, ["git", "diff"])
        changed = get_changed_files("origin/main")
        assert changed == []
        # Commands called should only reference origin/main, never HEAD~1 or status
        for call_args in mock_run.call_args_list:
            cmd = call_args[0][0]
            assert "HEAD~1" not in cmd
            assert "status" not in cmd
