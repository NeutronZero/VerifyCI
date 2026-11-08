"""Adversarial and boundary test suite for Milestone M1 Grounded Entity Mapping (§9.2, §15).

Tests:
1. Deleting top-level runtime statements is NOT safe other_text (must be INCONCLUSIVE).
2. Deleting safe module constructs (imports, docstrings) IS safe other_text.
3. Boundary hunks spanning multiple sibling entities produce INCONCLUSIVE (mapping_unresolved).
4. Boundary hunks within strict ancestor-descendant nesting chains map to the innermost entity.
5. Zero-hunk content-identical renames are explicitly tracked in scope.renames.
6. Zero-hunk content-identical renames triggering path deny rules produce FAIL.
7. Zero-hunk content-identical renames triggering symbol deny rules produce FAIL.
8. Bi-directional replacement of imports with top-level side effects produces INCONCLUSIVE.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import pytest

from verifyci.checks.base import CheckContext
from verifyci.checks import grounding
from verifyci.contracts.model import Coverage, Outcome
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope


def create_scenario_repo(
    target_dir: Path,
    base_files: dict[str, str],
    head_files: dict[str, str],
    policy_toml: str = "",
) -> tuple[GitRepo, str, str, str]:
    """Create a small Git repo with git plumbing for base and head commits."""
    target_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(target_dir)], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "core.autocrlf", "false"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "core.safecrlf", "false"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.name", "VerifyCI Tester"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "config", "user.email", "test@verifyci.dev"], check=True)

    # 1. Base commit
    for rel_path, content in base_files.items():
        f = target_dir / rel_path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")

    subprocess.run(["git", "-C", str(target_dir), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "commit", "-q", "-m", "base"], check=True)
    base_commit = subprocess.check_output(
        ["git", "-C", str(target_dir), "rev-parse", "HEAD"], text=True
    ).strip()
    merge_base = base_commit

    time.sleep(0.05)

    # 2. Head commit
    # Clean working tree
    for item in target_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    future_time = time.time() + 10
    for rel_path, content in head_files.items():
        f = target_dir / rel_path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
        os.utime(f, (future_time, future_time))

    subprocess.run(["git", "-C", str(target_dir), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(target_dir), "commit", "-q", "-m", "head"], check=True)
    head_commit = subprocess.check_output(
        ["git", "-C", str(target_dir), "rev-parse", "HEAD"], text=True
    ).strip()

    repo = GitRepo(target_dir)
    return repo, base_commit, merge_base, head_commit


@pytest.mark.adversarial
def test_adversarial_module_level_deletion_side_effect():
    """Deleting top-level runtime code is unsafe and must NOT be classified as safe other_text."""
    base_files = {
        "sample.py": "import os\n\nos.system('echo runtime side effect')\n\ndef helper():\n    return 42\n"
    }
    head_files = {
        "sample.py": "import os\n\ndef helper():\n    return 42\n"
    }
    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)

        assert len(scope.unmapped_hunks) == 1
        assert scope.unmapped_hunks[0]["reason_code"] == "mapping_unresolved"

        policy = parse_policy_bytes(b"[deny_changes]\n")
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.INCONCLUSIVE
        assert res.coverage == Coverage.PARTIAL
        assert "mapping_unresolved" in res.reason_codes


@pytest.mark.adversarial
def test_clean_module_level_deletion_safe_construct():
    """Deleting a safe module construct (e.g. unused import) IS classified as safe other_text."""
    base_files = {
        "sample.py": "import os\nimport sys\n\ndef helper():\n    return 42\n"
    }
    head_files = {
        "sample.py": "import os\n\ndef helper():\n    return 42\n"
    }
    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)

        assert len(scope.unmapped_hunks) == 0
        assert len(scope.mapped_hunks) == 1
        assert scope.mapped_hunks[0]["mapped_entity"] == "other_text"

        policy = parse_policy_bytes(b"[deny_changes]\n")
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.PASS
        assert res.coverage == Coverage.COMPLETE


@pytest.mark.adversarial
def test_adversarial_boundary_crossing_sibling_entities():
    """A hunk spanning boundaries of sibling entities must be rejected as ambiguous (INCONCLUSIVE)."""
    base_files = {
        "sample.py": (
            "def foo():\n"
            "    return 1\n"
            "def bar():\n"
            "    return 2\n"
        )
    }
    # A single hunk replaces end of foo and start of bar
    head_files = {
        "sample.py": (
            "def foo():\n"
            "    return 10\n"
            "def bar_changed():\n"
            "    return 2\n"
        )
    }
    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)

        assert len(scope.unmapped_hunks) == 1
        assert scope.unmapped_hunks[0]["reason_code"] == "mapping_unresolved"

        policy = parse_policy_bytes(b"[deny_changes]\n")
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.INCONCLUSIVE
        assert res.coverage == Coverage.PARTIAL
        assert "mapping_unresolved" in res.reason_codes


@pytest.mark.adversarial
def test_boundary_nested_entities_strict_containment():
    """When a hunk is inside a nested entity chain, the innermost entity is chosen."""
    base_files = {
        "sample.py": (
            "class Worker:\n"
            "    def execute(self):\n"
            "        return 'old'\n"
        )
    }
    head_files = {
        "sample.py": (
            "class Worker:\n"
            "    def execute(self):\n"
            "        return 'new'\n"
        )
    }
    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)

        assert len(scope.unmapped_hunks) == 0
        assert len(scope.mapped_hunks) == 1
        assert scope.mapped_hunks[0]["mapped_entity"] == "sample:Worker.execute"

        policy = parse_policy_bytes(b"[deny_changes]\n")
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.PASS
        assert res.coverage == Coverage.COMPLETE


@pytest.mark.adversarial
def test_zero_hunk_rename_clean_tracking():
    """Zero-hunk content-identical rename is explicitly recorded in scope.renames and passes."""
    content = "def calculate(x: int) -> int:\n    return x * 2\n"
    base_files = {"service/old_calc.py": content}
    head_files = {"service/new_calc.py": content}

    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        assert len(entries) == 1
        assert entries[0].is_renamed is True
        assert len(entries[0].hunks) == 0

        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)
        assert len(scope.renames) == 1
        rename_rec = scope.renames[0]
        assert rename_rec["base_path"] == "service/old_calc.py"
        assert rename_rec["head_path"] == "service/new_calc.py"
        assert rename_rec["mapping"] == "file_rename_content_identical"

        assert "service/old_calc:calculate" in scope.changed_entities
        assert "service/new_calc:calculate" in scope.changed_entities

        policy = parse_policy_bytes(b"[deny_changes]\n")
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.PASS
        assert res.coverage == Coverage.COMPLETE


@pytest.mark.adversarial
def test_adversarial_zero_hunk_rename_denied_by_path_rule():
    """Zero-hunk rename into a prohibited path pattern produces FAIL with GRD-UNGROUNDED-EDIT."""
    content = "def secret_key() -> str:\n    return 'secret'\n"
    base_files = {"internal/secret.py": content}
    head_files = {"public/secret.py": content}

    policy_bytes = (
        b"[deny_changes.block_public]\n"
        b'paths = ["public/**"]\n'
        b'reason = "public changes prohibited"\n'
    )

    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)

        policy = parse_policy_bytes(policy_bytes)
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.FAIL
        assert res.coverage == Coverage.COMPLETE
        assert len(res.findings) == 1
        finding = res.findings[0]
        assert finding.defect_id == "GRD-UNGROUNDED-EDIT"
        assert finding.reason_code == "policy_prohibited"
        assert finding.subject["path"] == "public/secret.py"
        assert finding.evidence.payload["primary_rule_id"] == "block_public"


@pytest.mark.adversarial
def test_adversarial_zero_hunk_rename_denied_by_symbol_rule():
    """Zero-hunk rename touching a prohibited symbol produces FAIL with GRD-UNGROUNDED-EDIT."""
    content = "def crypto_sign(msg: bytes) -> bytes:\n    return msg\n"
    base_files = {"service/old_service.py": content}
    head_files = {"service/new_service.py": content}

    policy_bytes = (
        b"[deny_changes.freeze_crypto]\n"
        b'symbols = ["service/*:crypto_sign"]\n'
        b'reason = "crypto functions are frozen"\n'
    )

    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)

        policy = parse_policy_bytes(policy_bytes)
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.FAIL
        assert res.coverage == Coverage.COMPLETE
        assert len(res.findings) >= 1
        f_symbols = {f.subject["symbol"] for f in res.findings}
        assert any("crypto_sign" in s for s in f_symbols)
        for f in res.findings:
            assert f.defect_id == "GRD-UNGROUNDED-EDIT"
            assert f.reason_code == "policy_prohibited"


@pytest.mark.adversarial
def test_adversarial_bidirectional_replacement_unsafe_construct():
    """Replacing safe imports with top-level side-effecting code produces INCONCLUSIVE."""
    base_files = {
        "sample.py": "import math\n\ndef helper():\n    return math.pi\n"
    }
    head_files = {
        "sample.py": "import os\nos.system('curl http://malicious.site')\n\ndef helper():\n    return 3.14\n"
    }
    with tempfile.TemporaryDirectory() as td:
        repo, base_c, mb, head_c = create_scenario_repo(Path(td), base_files, head_files)
        entries, rename_limit = repo.diff_entries(base_c, head_c)
        scope = build_changed_scope(entries, rename_limit_exceeded=rename_limit)

        # The hunk replacing import math with os.system is unmapped
        assert any(h["reason_code"] == "mapping_unresolved" for h in scope.unmapped_hunks)

        policy = parse_policy_bytes(b"[deny_changes]\n")
        context = CheckContext(
            git=repo,
            policy=policy,
            entries=tuple(entries),
            scope=scope,
            as_of_date="2026-10-22",
            object_format="sha1",
            target_base_commit=base_c,
            merge_base_commit=mb,
            head_commit=head_c,
            toolchain_fingerprint="sha256:test",
            rename_limit_exceeded=rename_limit,
        )
        res = grounding.run(context)
        assert res.outcome == Outcome.INCONCLUSIVE
        assert res.coverage == Coverage.PARTIAL
        assert "mapping_unresolved" in res.reason_codes
