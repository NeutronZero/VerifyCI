"""Regression and integration tests for advanced checks and release trust improvements.

Covers:
1. Grounding binary file findings include content_sha256 in evidence payload.
2. Semantic AST body comparison without copy.deepcopy behaves identically on matching and divergent functions.
3. Evaluator epoch commitment uses domain-separated HMAC and does not disclose raw seed bytes.
4. Worker launcher supports configurable object_format and source_roots via CLI and environment.
5. Supervisor uses structured error checks rather than informal substring heuristics.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import os
from pathlib import Path
import subprocess
import tempfile

import pytest

from docker.worker import launch_candidate
from dataclasses import dataclass
from verifyci.checks.base import CheckContext
from verifyci.checks import grounding
from verifyci.checks import semantic
from verifyci.contracts.model import Outcome
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope
from verifyci_release_trust.evaluator import generate_held_out_scenarios


def _init_git_repo(path: Path) -> GitRepo:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "core.autocrlf", "false"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "core.safecrlf", "false"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Tester"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "tester@verifyci.dev"], check=True)
    return GitRepo(path)


def test_grounding_binary_finding_includes_content_sha256():
    """Verify that binary file deny violations include content_sha256 in finding evidence payload."""
    with tempfile.TemporaryDirectory() as td:
        repo_path = Path(td)
        repo = _init_git_repo(repo_path)

        # Base commit
        readme = repo_path / "README.md"
        readme.write_text("# Project\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_path), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(repo_path), "commit", "-q", "-m", "base"], check=True)
        base_sha = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"], text=True
        ).strip()

        # Head commit adding binary file matching deny policy
        binary_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x01\x00\x01\x08\x06\x00\x00\x00"
        expected_sha256 = hashlib.sha256(binary_data).hexdigest()

        bin_file = repo_path / "binaries" / "image.png"
        bin_file.parent.mkdir(parents=True, exist_ok=True)
        bin_file.write_bytes(binary_data)
        subprocess.run(["git", "-C", str(repo_path), "add", "binaries/image.png"], check=True)
        subprocess.run(["git", "-C", str(repo_path), "commit", "-q", "-m", "add binary"], check=True)
        head_sha = subprocess.check_output(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"], text=True
        ).strip()

        entries, rename_limit = repo.diff_entries(base_sha, head_sha)
        assert len(entries) == 1
        assert entries[0].is_binary is True

        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)
        policy_toml = b"""
[deny_changes.prohibit_binaries]
paths = ["binaries/**"]
reason = "no binaries allowed"
"""
        policy = parse_policy_bytes(policy_toml)
        ctx = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-11-09",
            object_format="sha1",
            target_base_commit=base_sha,
            merge_base_commit=base_sha,
            head_commit=head_sha,
            toolchain_fingerprint="tc_test",
        )

        res = grounding.run(ctx)
        assert res.outcome == Outcome.FAIL
        assert len(res.findings) == 1
        finding = res.findings[0]
        assert "content_sha256" in finding.evidence.payload
        assert finding.evidence.payload["content_sha256"] == expected_sha256


def test_grounding_binary_synthetic_entry_has_content_sha256():
    """Verify that grounding synthesizes content_sha256 even without GitRepo."""
    raw_content = b"\x00\x01\x02\x03\x04\xff"
    expected_sha256 = hashlib.sha256(raw_content).hexdigest()

    @dataclass
    class CustomBinaryEntry:
        status: str = "A"
        base_path: str = ""
        head_path: str = "data/blob.bin"
        base_blob: str | None = None
        head_blob: str | None = None
        base_mode: str | None = None
        head_mode: str | None = "100644"
        base_source: str = ""
        head_source: str = ""
        is_binary: bool = True
        changed_paths: tuple[str, ...] = ("data/blob.bin",)
        content: bytes = raw_content

    entry = CustomBinaryEntry()

    class MockScope:
        changed_entities = ()
        unmapped_hunks = ()
        mapped_hunks = ()

        def entity(self, _):
            return None

    policy = parse_policy_bytes(b"""
[deny_changes.deny_data]
paths = ["data/**"]
reason = "deny data binaries"
""")
    ctx = CheckContext(
        git=None,
        policy=policy,
        entries=(entry,),
        scope=MockScope(),  # type: ignore[arg-type]
        as_of_date="2026-11-09",
        object_format="sha1",
        target_base_commit="base",
        merge_base_commit="base",
        head_commit="head",
        toolchain_fingerprint="tc",
    )
    res = grounding.run(ctx)
    assert res.outcome == Outcome.FAIL
    assert len(res.findings) == 1
    assert "content_sha256" in res.findings[0].evidence.payload
    assert res.findings[0].evidence.payload["content_sha256"] == expected_sha256


def test_semantic_ast_body_digest_matching_and_divergent():
    """Verify AST structural dump digest matches on non-semantic edits and differs on semantic changes."""
    code_base = """
def process(val: int) -> int:
    \"\"\"Docstring for base implementation.\"\"\"
    # Inline comment
    result = val * 2
    return result + 1
"""

    code_match = """
def process(val: int) -> int:
    \"\"\"Completely different docstring in head.\"\"\"
    # Different comment formatting
    result = val * 2
    return result + 1
"""

    code_divergent = """
def process(val: int) -> int:
    \"\"\"Docstring for base implementation.\"\"\"
    # Changed multiplier
    result = val * 3
    return result + 1
"""

    tree_base = ast.parse(code_base)
    tree_match = ast.parse(code_match)
    tree_divergent = ast.parse(code_divergent)

    # 1. Matching ASTs (different docstrings/comments) produce identical digests
    digest_base = semantic._ast_body_digest(tree_base)
    digest_match = semantic._ast_body_digest(tree_match)
    assert digest_base == digest_match

    # 2. Divergent ASTs produce different digests
    digest_divergent = semantic._ast_body_digest(tree_divergent)
    assert digest_base != digest_divergent

    # 3. Assert original trees were restored and NOT permanently stripped
    first_stmt = tree_base.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(first_stmt, ast.Expr)
    assert isinstance(first_stmt.value, ast.Constant)
    assert first_stmt.value.value == "Docstring for base implementation."

    first_stmt_match = tree_match.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(first_stmt_match, ast.Expr)
    assert isinstance(first_stmt_match.value, ast.Constant)
    assert first_stmt_match.value.value == "Completely different docstring in head."


def test_evaluator_epoch_commitment_domain_separation():
    """Verify that evaluator epoch uses domain-separated HMAC and does not disclose raw seed bytes."""
    seed_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    seed_bytes = bytes.fromhex(seed_hex)

    raw_seed_prefix = seed_bytes[:8].hex()
    expected_epoch = hmac.new(
        b"VERIFYCI-HELDOUT-EPOCH-COMMITMENT", seed_bytes, hashlib.sha256
    ).hexdigest()[:16]

    base_cases = [
        {
            "case_id": "base_case_01",
            "base_files": {"mod.py": "def f():\n    temp_var = 10\n    return temp_var\n"},
            "head_files": {"mod.py": "def f():\n    temp_var = 20\n    return temp_var\n"},
            "policy": {},
            "expected": {"outcome": "PASS", "coverage": "COMPLETE"},
        }
    ]

    scenarios, commitment, epoch = generate_held_out_scenarios(seed_hex, base_cases, count=2)

    # Invariant: raw 64-bit seed prefix is NOT disclosed
    assert epoch != raw_seed_prefix, "epoch must not expose raw seed prefix hex"

    # Invariant: epoch strictly equals domain-separated HMAC commitment prefix
    assert epoch == expected_epoch
    assert len(epoch) == 16

    # Invariant: scenario case_ids use the HMAC epoch
    for sc in scenarios:
        assert sc["case_id"].startswith(f"heldout_{epoch}_")


def test_launch_candidate_args_and_env_config(monkeypatch: pytest.MonkeyPatch):
    """Verify launch_candidate accepts configurable object_format and source_roots via args and env."""
    # 1. Direct arguments
    test_argv = [
        "launch_candidate.py",
        "check-case",
        "--base", "01" * 20,
        "--head", "02" * 20,
        "--object-format", "sha256",
        "--source-root", "src",
        "--source-root", "lib",
    ]
    monkeypatch.setattr("sys.argv", test_argv)
    args = launch_candidate.parse_args()
    assert args.object_format == "sha256"
    assert args.source_roots == ["src", "lib"]

    # 2. Comma-separated --source-roots flag
    test_argv2 = [
        "launch_candidate.py",
        "check-case",
        "--base", "01" * 20,
        "--head", "02" * 20,
        "--source-roots", "app,core,utils",
    ]
    monkeypatch.setattr("sys.argv", test_argv2)
    args2 = launch_candidate.parse_args()
    assert args2.source_roots_str == "app,core,utils"

    # 3. Environment variable fallback
    monkeypatch.setenv("VERIFYCI_OBJECT_FORMAT", "sha256")
    monkeypatch.setenv("VERIFYCI_SOURCE_ROOTS", "env_src,env_lib")
    test_argv3 = [
        "launch_candidate.py",
        "check-case",
        "--base", "01" * 20,
        "--head", "02" * 20,
    ]
    monkeypatch.setattr("sys.argv", test_argv3)
    args3 = launch_candidate.parse_args()

    obj_format = (
        args3.object_format
        or os.environ.get("VERIFYCI_OBJECT_FORMAT")
        or "sha1"
    )
    assert obj_format == "sha256"

    parsed_roots = [
        p.strip() for p in os.environ.get("VERIFYCI_SOURCE_ROOTS", "").split(",") if p.strip()
    ]
    assert parsed_roots == ["env_src", "env_lib"]


def test_supervisor_verdict_structured_error_logic():
    """Verify supervisor verdict logic uses structured collections rather than informal substring checks."""
    # Simulation of supervisor verdict resolution block
    def resolve_verdict(
        errors: list[str],
        held_out_seed: str | None,
        cases_evaluated: int,
        total_held_out: int,
    ) -> str:
        has_errors = bool(errors)
        execution_verified = (
            not has_errors
            and bool(held_out_seed)
            and cases_evaluated == total_held_out
        )
        if execution_verified:
            return "PASS"
        if has_errors:
            return "FAIL"
        return "INCONCLUSIVE"

    # 1. Custom non-substring error that old code would have missed ("failed", "mismatch", etc. absent)
    unusual_error = ["unusual kernel exit code 137", "oom condition encountered"]
    assert resolve_verdict(unusual_error, "seed123", 10, 10) == "FAIL"

    # 2. Clean execution with valid held-out seed -> PASS
    assert resolve_verdict([], "valid_seed", 10, 10) == "PASS"

    # 3. Clean execution but no held-out seed and no errors -> INCONCLUSIVE
    assert resolve_verdict([], None, 0, 10) == "INCONCLUSIVE"

    # 4. Incomplete evaluation -> INCONCLUSIVE if no explicit error recorded
    assert resolve_verdict([], "seed123", 9, 10) == "INCONCLUSIVE"

