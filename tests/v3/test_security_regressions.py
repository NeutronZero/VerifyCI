"""Regression and adversarial tests for VerifyCI M4 Security analysis engine."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from verifyci.checks.base import CheckContext
from verifyci.checks.security import run as run_security
from verifyci.contracts.model import CheckResult, Coverage, Outcome
from verifyci.gate.orchestrator import _augment_scope_with_repository
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope


def _build_and_run(
    case_id: str,
    base_files: dict[str, str],
    head_files: dict[str, str],
    policy_toml: str,
    tmp_path: Path,
) -> CheckResult:
    repo_dir = tmp_path / case_id
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    repo_dir.mkdir(parents=True)

    subprocess.run(["git", "init", "-q", "-b", "main", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "TestRunner"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@verifyci.dev"], check=True, capture_output=True)

    for rel_path, content in base_files.items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-q", "-m", "base"], check=True, capture_output=True)
    base_commit = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

    for item in repo_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    for rel_path, content in head_files.items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-q", "-m", "head", "--allow-empty"], check=True, capture_output=True)
    head_commit = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

    repo = GitRepo(repo_dir)
    entries, _ = repo.diff_entries(base_commit, head_commit)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(
        scope, git=repo, base_rev=base_commit, head_rev=head_commit, source_roots=()
    )

    policy = parse_policy_bytes(policy_toml.encode("utf-8"))
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base_commit,
        merge_base_commit=base_commit,
        head_commit=head_commit,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    return run_security(ctx)


@pytest.mark.invariant
def test_precedence_fail_beats_inconclusive(tmp_path: Path):
    """When a validated secret is found alongside an unresolved taint path, FAIL takes precedence."""
    base = {"src/app.py": "def handle(): pass\n"}
    head = {
        "src/app.py": (
            "AWS_KEY = \"AKIA1234567890ABCDEF\"\n"
            "def handle():\n"
            "    user = request.args.get('id')\n"
            "    return user\n"
        )
    }
    policy = (
        "[taint]\n"
        "sources = [\"request.args\"]\n"
        "[taint.sinks.db]\n"
        "symbols = [\"cursor:execute\"]\n"
        "kind = \"sql\"\n"
    )
    res = _build_and_run("prec_fail", base, head, policy, tmp_path)
    assert res.outcome == Outcome.FAIL
    assert res.coverage == Coverage.PARTIAL
    assert any(f.defect_id == "SEC-SECRET" for f in res.findings)
    assert "taint_path_unresolved" in res.reason_codes


@pytest.mark.invariant
def test_allowlist_selectivity(tmp_path: Path):
    """Allowlisted paths pass secrets safely, but non-allowlisted files in the same diff fail."""
    base = {
        "fixtures/sample.py": "# empty\n",
        "src/prod.py": "def init(): pass\n",
    }
    head = {
        "fixtures/sample.py": "TEST_KEY = \"AKIA1234567890ABCDEF\"\n",
        "src/prod.py": "PROD_KEY = \"AKIA0987654321FEDCBA\"\ndef init(): pass\n",
    }
    policy = "[secrets]\nallowlist_paths = [\"fixtures/**\"]\n"
    res = _build_and_run("allowlist_selective", base, head, policy, tmp_path)
    assert res.outcome == Outcome.FAIL
    assert len(res.findings) == 1
    assert res.findings[0].subject["path"] == "src/prod.py"


@pytest.mark.invariant
def test_custom_placeholders_respected(tmp_path: Path):
    """Custom placeholder patterns from target-base policy are ignored as secrets."""
    base = {"src/conf.py": "def cfg(): pass\n"}
    head = {
        "src/conf.py": (
            "api_key = \"mock_sandbox_key_for_testing\"\n"
            "def cfg(): return api_key\n"
        )
    }
    policy = "[secrets]\nplaceholder_patterns = [\"mock_sandbox_key_for_testing\"]\n"
    res = _build_and_run("custom_placeholder", base, head, policy, tmp_path)
    assert res.outcome == Outcome.PASS
    assert res.coverage == Coverage.COMPLETE
    assert not res.findings


@pytest.mark.invariant
def test_strict_redaction_across_multiple_secrets(tmp_path: Path):
    """Every detected secret must be 100% redacted in findings, evidence, and messages."""
    raw_secrets = [
        "AKIA1234567890ABCDEF",
        "ghp_123456789012345678901234",
        "rk_live_0123456789ABCDEF0123",
    ]
    base = {"src/keys.py": "def get(): pass\n"}
    head = {
        "src/keys.py": "\n".join(f"K{i} = \"{s}\"" for i, s in enumerate(raw_secrets)) + "\n"
    }
    res = _build_and_run("redaction_multi", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    assert len(res.findings) == 3
    for f in res.findings:
        payload = f.evidence.payload
        redacted = payload.get("redacted", "")
        assert "…" in redacted
        for s in raw_secrets:
            assert s not in f.message
            assert s not in json.dumps(payload)


@pytest.mark.invariant
def test_unsupported_language_taint_unknown_coverage(tmp_path: Path):
    """Diff touching an unsupported language file under configured taint policy yields UNKNOWN coverage."""
    base = {"lib/core.rs": "fn run() {}\n"}
    head = {"lib/core.rs": "fn run() { let x = 1; }\n"}
    policy = (
        "[taint]\n"
        "sources = [\"request.args\"]\n"
        "[taint.sinks.db]\n"
        "symbols = [\"cursor:execute\"]\n"
        "kind = \"sql\"\n"
    )
    res = _build_and_run("unsupported_taint", base, head, policy, tmp_path)
    assert res.outcome == Outcome.INCONCLUSIVE
    assert res.coverage == Coverage.UNKNOWN
    assert "unsupported_language" in res.reason_codes
    assert not res.findings
