"""Regression tests for contract check caller resolution and public API compatibility."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess

import pytest

from verifyci.checks.base import CheckContext
from verifyci.checks.contract import run as run_contract
from verifyci.contracts.model import CheckResult, Coverage, Outcome
from verifyci.gate.orchestrator import _augment_scope_with_repository
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope


def _build_and_run(
    case_id: str,
    base_files: dict[str, str],
    head_files: dict[str, str],
    public_api: list[str] | None,
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

    toml = b""
    if public_api:
        toml = b"[public_api]\nsymbols = " + repr(public_api).encode() + b"\n"

    policy = parse_policy_bytes(toml)
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
    return run_contract(ctx)


@pytest.mark.invariant
def test_different_modules_identical_function_names(tmp_path: Path):
    """Call to legacy.parse must not be attributed to service.parse."""
    base_files = {
        "src/service.py": "def parse(text: str) -> str:\n    return text\n",
        "src/service_caller.py": "from src.service import parse\n\ndef run_service():\n    return parse('hello')\n",
        "src/legacy.py": "def parse(val: int) -> int:\n    return val\n",
        "src/legacy_caller.py": "from src.legacy import parse\n\ndef run_legacy():\n    return parse(42)\n",
    }
    head_files = {
        # service.parse signature changes to require 3 args
        "src/service.py": "def parse(text: str, strict: bool, mode: str) -> str:\n    return text\n",
        # service_caller is migrated to match the new 3-argument signature
        "src/service_caller.py": "from src.service import parse\n\ndef run_service():\n    return parse('hello', True, 'fast')\n",
        # legacy.parse is unchanged (1 argument)
        "src/legacy.py": "def parse(val: int) -> int:\n    return val\n",
        # legacy_caller calls legacy.parse with 1 arg
        "src/legacy_caller.py": "from src.legacy import parse\n\ndef run_legacy():\n    return parse(42)\n",
    }
    result = _build_and_run("identical_names", base_files, head_files, None, tmp_path)
    # The unrelated call to legacy.parse (1 arg) must NOT be attributed to service.parse (3 args).
    # Since service_caller was properly migrated, there are 0 broken callers.
    assert result.outcome == Outcome.PASS
    assert len(result.findings) == 0
    # Because service.parse has no callers in repo and is not public, outcome is PASS.
    assert result.outcome == Outcome.PASS
    assert len(result.findings) == 0


@pytest.mark.invariant
def test_aliased_import_signature_break(tmp_path: Path):
    """Incompatible call through an import alias must be detected."""
    base_files = {
        "src/service.py": "def parse(text: str) -> str:\n    return text\n",
        "src/caller.py": "from src.service import parse as custom_parse\n\ndef run():\n    return custom_parse('hello')\n",
    }
    head_files = {
        "src/service.py": "def parse(text: str, encoding: str) -> str:\n    return text\n",
        "src/caller.py": "from src.service import parse as custom_parse\n\ndef run():\n    return custom_parse('hello')\n",
    }
    result = _build_and_run("aliased_import", base_files, head_files, None, tmp_path)
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.defect_id == "CTR-SIGNATURE-BREAK"
    assert finding.subject["symbol"] == "src/service:parse"
    assert finding.premises["problem"] == "too_few_positional_arguments"


@pytest.mark.invariant
def test_unresolved_binding_dynamic_target_gap(tmp_path: Path):
    """Ambiguous/unresolved call site must yield a coverage gap rather than a guessed target."""
    base_files = {
        "src/service.py": "def run(token: str) -> bool:\n    return True\n",
        "src/service_caller.py": "from src.service import run\n\ndef call_it():\n    return run('token')\n",
        "src/caller.py": "def execute():\n    return run('token')\n",
    }
    head_files = {
        "src/service.py": "def run(token: str, secret: str) -> bool:\n    return True\n",
        "src/service_caller.py": "from src.service import run\n\ndef call_it():\n    return run('token', 'secret')\n",
        "src/caller.py": "def execute():\n    return run('token')\n",
    }
    result = _build_and_run("unresolved_binding", base_files, head_files, None, tmp_path)
    assert result.outcome == Outcome.INCONCLUSIVE
    assert result.coverage == Coverage.PARTIAL
    assert any(g.reason_code == "dynamic_target_unresolved" for g in result.coverage_gaps)
    assert len(result.findings) == 0


@pytest.mark.invariant
def test_public_api_optional_parameter_added_compatible(tmp_path: Path):
    """Adding an optional parameter with default to a declared public API is compatible."""
    base_files = {
        "src/api.py": "def query(sql: str) -> list:\n    return []\n",
    }
    head_files = {
        "src/api.py": "def query(sql: str, timeout: int = 30) -> list:\n    return []\n",
    }
    result = _build_and_run(
        "public_api_compatible", base_files, head_files, ["src/api:query"], tmp_path
    )
    assert result.outcome == Outcome.PASS
    assert result.coverage == Coverage.COMPLETE
    assert len(result.findings) == 0


@pytest.mark.invariant
def test_public_api_required_parameter_added_break(tmp_path: Path):
    """Adding a required parameter without default to a declared public API is a signature break."""
    base_files = {
        "src/api.py": "def query(sql: str) -> list:\n    return []\n",
    }
    head_files = {
        "src/api.py": "def query(sql: str, timeout: int) -> list:\n    return []\n",
    }
    result = _build_and_run(
        "public_api_break", base_files, head_files, ["src/api:query"], tmp_path
    )
    assert result.outcome == Outcome.FAIL
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.defect_id == "CTR-SIGNATURE-BREAK"
    assert finding.subject["symbol"] == "src/api:query"
    assert "required_positional_parameters_added" in finding.premises["problems"]


@pytest.mark.invariant
def test_uncalled_private_function_signature_change_safe(tmp_path: Path):
    """Incompatible signature change to an uncalled private function must not break contract."""
    base_files = {
        "src/utils.py": "def _secret_helper(x: int) -> int:\n    return x\n",
    }
    head_files = {
        # Private helper gains required parameter, but has 0 repo callers and is not public
        "src/utils.py": "def _secret_helper(x: int, salt: str) -> int:\n    return x\n",
    }
    result = _build_and_run("uncalled_private", base_files, head_files, None, tmp_path)
    assert result.outcome == Outcome.PASS
    assert len(result.findings) == 0


@pytest.mark.invariant
def test_same_file_call_shadowed_by_local_binding(tmp_path: Path):
    """Same-file call shadowed by a local binding must not be attributed to module target."""
    base_files = {
        "src/service.py": (
            "def helper(x: int) -> int:\n"
            "    return x\n\n"
            "def call_valid():\n"
            "    return helper(1)\n\n"
            "def compute():\n"
            "    helper = lambda a: a * 2\n"
            "    return helper(10)\n"
        ),
    }
    head_files = {
        # helper updated to 2 arguments
        # call_valid updated to 2 arguments
        # compute has local lambda with 1 argument (shadowing helper)
        "src/service.py": (
            "def helper(x: int, y: int) -> int:\n"
            "    return x + y\n\n"
            "def call_valid():\n"
            "    return helper(1, 2)\n\n"
            "def compute():\n"
            "    helper = lambda a: a * 2\n"
            "    return helper(10)\n"
        ),
    }
    result = _build_and_run("same_file_shadowing", base_files, head_files, None, tmp_path)
    # The shadowed call helper(10) in compute must NOT be attributed to module helper(x, y).
    # call_valid is compatible, so outcome is PASS with 0 findings.
    assert result.outcome == Outcome.PASS
    assert len(result.findings) == 0

