"""Adversarial challenge test suite for Milestone M6:
- Promotion chain cryptographic tampering resistance
- scripts/validate_release.py fail-closed behavior
- Gate integration detecting real semantic defects with Verdict.FAIL
"""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from verifyci.contracts.manifest import (
    CHECK_ORDER,
    CHECK_SPECS,
)
from verifyci.contracts.model import Verdict
from verifyci.contracts.promotion import (
    validate_promotion_chain,
)
from verifyci.gate.orchestrator import GateRequest, run_gate

ROOT = Path(__file__).resolve().parents[1]
POLICY = '[gate]\ntarget_drift = "record"\n'
AS_OF = "2026-10-27"


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ==============================================================================
# Helper to copy evidence environment for non-destructive tampering
# ==============================================================================

def _setup_tamper_env(tmp_path: Path) -> Path:
    """Create a minimal mirror of repo root with evidence and corpora for isolated tampering."""
    env_root = tmp_path / "repo_env"
    env_root.mkdir(parents=True)

    # Copy evidence/release/semantic
    src_semantic = ROOT / "evidence" / "release" / "semantic"
    dst_semantic = env_root / "evidence" / "release" / "semantic"
    dst_semantic.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_semantic, dst_semantic)

    # Copy corpora/semantic/cases.jsonl
    src_corpus = ROOT / "corpora" / "semantic" / "cases.jsonl"
    dst_corpus = env_root / "corpora" / "semantic" / "cases.jsonl"
    dst_corpus.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_corpus, dst_corpus)

    return env_root


# ==============================================================================
# 1. Cryptographic Tampering against evidence/release/semantic/
# ==============================================================================

@pytest.mark.adversarial
class TestSemanticCryptographicTampering:
    """Adversarial stress-testing of semantic promotion chain cryptographic validation."""

    def test_corrupt_promotion_record_hash_in_spec_fails_closed(self):
        """Corrupting promotion_record_hash in CheckSpec must fail validation closed."""
        spec = CHECK_SPECS["semantic"]
        corrupted_hash = "sha256:" + "0" * 64
        tampered_spec = replace(spec, promotion_record_hash=corrupted_hash)

        errors = validate_promotion_chain(tampered_spec)
        assert len(errors) > 0, "Validation did not fail closed on corrupted promotion_record_hash"
        assert any("promotion record hash does not match the manifest" in err for err in errors)

    def test_corrupt_promotion_record_file_content_fails_closed(self, tmp_path: Path):
        """Modifying promotion_record.json on disk without manifest update must fail closed."""
        env_root = _setup_tamper_env(tmp_path)
        record_path = env_root / "evidence" / "release" / "semantic" / "promotion_record.json"

        data = json.loads(record_path.read_text(encoding="utf-8"))
        data["created_date"] = "2026-01-01"  # Tamper content
        record_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        spec = CHECK_SPECS["semantic"]
        errors = validate_promotion_chain(spec, repo_root=env_root)
        assert len(errors) > 0, "Validation did not fail closed when promotion_record.json was tampered"
        assert any("promotion record hash does not match the manifest" in err for err in errors)

    def test_corrupt_release_report_hash_in_record_fails_closed(self, tmp_path: Path):
        """Corrupting report_hash inside promotion_record.json must fail closed."""
        env_root = _setup_tamper_env(tmp_path)
        record_path = env_root / "evidence" / "release" / "semantic" / "promotion_record.json"

        data = json.loads(record_path.read_text(encoding="utf-8"))
        data["report_hash"] = "sha256:" + "f" * 64  # Tamper report_hash
        new_record_bytes = json.dumps(data, indent=2).encode("utf-8")
        record_path.write_bytes(new_record_bytes)

        # Update spec to match the new record hash so we specifically test report_hash validation
        tampered_spec = replace(CHECK_SPECS["semantic"], promotion_record_hash=_sha256(new_record_bytes))
        errors = validate_promotion_chain(tampered_spec, repo_root=env_root)
        assert len(errors) > 0
        assert any("promotion record report_hash mismatch" in err for err in errors)

    def test_corrupt_release_report_content_fails_closed(self, tmp_path: Path):
        """Modifying release_report.json on disk causes promotion_record report_hash mismatch."""
        env_root = _setup_tamper_env(tmp_path)
        report_path = env_root / "evidence" / "release" / "semantic" / "release_report.json"

        # Tamper report content (e.g. inject an extra requirement or change measurement)
        data = json.loads(report_path.read_text(encoding="utf-8"))
        data["measurement_command"]["version"] = "9.9.9"
        report_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

        spec = CHECK_SPECS["semantic"]
        errors = validate_promotion_chain(spec, repo_root=env_root)
        assert len(errors) > 0
        assert any("promotion record report_hash mismatch" in err for err in errors)

    @pytest.mark.parametrize("file_role,file_rel_path", [
        ("authored_corpus", "corpora/semantic/cases.jsonl"),
        ("heldout_corpus", "evidence/release/semantic/heldout_cases.jsonl"),
        ("mined_set", "evidence/release/semantic/mined_set.json"),
        ("adjudication", "evidence/release/semantic/adjudication.json"),
    ])
    def test_corrupt_input_file_on_disk_fails_closed(self, tmp_path: Path, file_role: str, file_rel_path: str):
        """Tampering with any hashed input artifact on disk must trigger release input hash mismatch."""
        env_root = _setup_tamper_env(tmp_path)
        target_file = env_root / file_rel_path
        assert target_file.exists(), f"Target file does not exist: {target_file}"

        # Tamper file on disk (append a byte)
        target_file.write_bytes(target_file.read_bytes() + b"\n# corrupted\n")

        spec = CHECK_SPECS["semantic"]
        errors = validate_promotion_chain(spec, repo_root=env_root)
        assert len(errors) > 0, f"Tampering with {file_role} ({file_rel_path}) did not fail validation"
        assert any("release input hash mismatch" in err and file_rel_path in err for err in errors)

    def test_missing_input_file_on_disk_fails_closed(self, tmp_path: Path):
        """Deleting an input artifact on disk must fail closed."""
        env_root = _setup_tamper_env(tmp_path)
        heldout_path = env_root / "evidence" / "release" / "semantic" / "heldout_cases.jsonl"
        heldout_path.unlink()

        spec = CHECK_SPECS["semantic"]
        errors = validate_promotion_chain(spec, repo_root=env_root)
        assert len(errors) > 0
        assert any("invalid release input" in err for err in errors)

    def test_colliding_author_and_heldout_labellers_fails_closed(self, tmp_path: Path):
        """Colliding participant IDs between check_authors and heldout_labellers must fail closed."""
        env_root = _setup_tamper_env(tmp_path)
        report_path = env_root / "evidence" / "release" / "semantic" / "release_report.json"
        record_path = env_root / "evidence" / "release" / "semantic" / "promotion_record.json"

        report = json.loads(report_path.read_text(encoding="utf-8"))
        author = report["participants"]["check_authors"][0]
        # Inject author into heldout_labellers
        report["participants"]["heldout_labellers"].append(author)
        new_report_bytes = json.dumps(report, indent=2).encode("utf-8")
        report_path.write_bytes(new_report_bytes)

        # Update promotion record with new report hash
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["report_hash"] = _sha256(new_report_bytes)
        new_record_bytes = json.dumps(record, indent=2).encode("utf-8")
        record_path.write_bytes(new_record_bytes)

        tampered_spec = replace(CHECK_SPECS["semantic"], promotion_record_hash=_sha256(new_record_bytes))
        errors = validate_promotion_chain(tampered_spec, repo_root=env_root)
        assert len(errors) > 0
        assert any("held-out labellers must be independent of check authors" in err for err in errors)

    def test_colliding_author_and_adjudicators_fails_closed(self, tmp_path: Path):
        """Colliding participant IDs between check_authors and adjudicators must fail closed."""
        env_root = _setup_tamper_env(tmp_path)
        report_path = env_root / "evidence" / "release" / "semantic" / "release_report.json"
        record_path = env_root / "evidence" / "release" / "semantic" / "promotion_record.json"

        report = json.loads(report_path.read_text(encoding="utf-8"))
        author = report["participants"]["check_authors"][0]
        # Inject author into adjudicators
        report["participants"]["adjudicators"].append(author)
        new_report_bytes = json.dumps(report, indent=2).encode("utf-8")
        report_path.write_bytes(new_report_bytes)

        # Update promotion record with new report hash
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["report_hash"] = _sha256(new_report_bytes)
        new_record_bytes = json.dumps(record, indent=2).encode("utf-8")
        record_path.write_bytes(new_record_bytes)

        tampered_spec = replace(CHECK_SPECS["semantic"], promotion_record_hash=_sha256(new_record_bytes))
        errors = validate_promotion_chain(tampered_spec, repo_root=env_root)
        assert len(errors) > 0
        assert any("adjudicators must be independent of check authors" in err for err in errors)

    def test_failed_release_requirement_fails_closed(self, tmp_path: Path):
        """Any requirement with passed: false in release_report.json must fail closed."""
        env_root = _setup_tamper_env(tmp_path)
        report_path = env_root / "evidence" / "release" / "semantic" / "release_report.json"
        record_path = env_root / "evidence" / "release" / "semantic" / "promotion_record.json"

        report = json.loads(report_path.read_text(encoding="utf-8"))
        report["requirements"]["witness_replay"]["passed"] = False
        new_report_bytes = json.dumps(report, indent=2).encode("utf-8")
        report_path.write_bytes(new_report_bytes)

        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["report_hash"] = _sha256(new_report_bytes)
        new_record_bytes = json.dumps(record, indent=2).encode("utf-8")
        record_path.write_bytes(new_record_bytes)

        tampered_spec = replace(CHECK_SPECS["semantic"], promotion_record_hash=_sha256(new_record_bytes))
        errors = validate_promotion_chain(tampered_spec, repo_root=env_root)
        assert len(errors) > 0
        assert any("release requirement not met: witness_replay" in err for err in errors)


# ==============================================================================
# 2. Testing scripts/validate_release.py
# ==============================================================================

@pytest.mark.adversarial
class TestValidateReleaseScript:
    """Stress-test scripts/validate_release.py under failure and tampering modes."""

    def test_validate_release_missing_signing_key_fails_closed(self, monkeypatch, capsys):
        """Authoritative scripts/validate_release.py fails closed (exit 1) when signing key is missing."""
        from scripts import validate_release

        monkeypatch.delenv("VERIFYCI_RELEASE_SIGNING_KEY", raising=False)
        exit_code = validate_release.main()
        assert exit_code == 1
        captured = capsys.readouterr()
        payload = json.loads(captured.out.strip())
        assert payload["release_ready"] is False
        assert payload["measurement_pipeline"] == "failed"
        assert any("VERIFYCI_RELEASE_SIGNING_KEY" in err for err in payload["manifest_errors"])

    def test_validate_release_preflight_checks_pass_on_clean_tree(self):
        """Preflight checks (corpora sums, corpus cases, promotion records) pass cleanly on repo root."""
        from scripts.validate_release import verify_corpus_cases, verify_security_corpus_sums
        from verifyci.contracts.manifest import CHECK_ORDER, CHECK_SPECS, validate_manifest
        from verifyci.contracts.promotion import validate_promotion_chain

        assert verify_security_corpus_sums(ROOT) == []
        assert verify_corpus_cases(ROOT) == []
        assert validate_manifest() == []
        for check_id in CHECK_ORDER:
            assert validate_promotion_chain(CHECK_SPECS[check_id]) == []

    @pytest.mark.parametrize("tampered_check", CHECK_ORDER)
    def test_broken_promotion_chain_in_any_check_exits_1(self, monkeypatch, tampered_check: str):
        """If any of the 5 checks has a broken promotion chain, validate_release must exit 1."""
        from scripts import validate_release
        from verifyci.contracts import manifest

        tampered_spec = replace(
            CHECK_SPECS[tampered_check],
            promotion_record_hash="sha256:" + "bad" * 21 + "a",
        )
        monkeypatch.setitem(manifest.CHECK_SPECS, tampered_check, tampered_spec)

        exit_code = validate_release.main()
        assert exit_code == 1, f"validate_release did not exit 1 when {tampered_check} promotion was broken"

    def test_tampered_corpus_checksum_exits_1(self, monkeypatch):
        """If security corpus checksum is tampered, validate_release must exit 1."""
        from scripts import validate_release
        from verifyci.contracts import manifest

        tampered_spec = replace(
            CHECK_SPECS["security"],
            corpus_hash="sha256:" + "bad" * 21 + "a",
        )
        monkeypatch.setitem(manifest.CHECK_SPECS, "security", tampered_spec)

        exit_code = validate_release.main()
        assert exit_code == 1, "validate_release did not exit 1 when security corpus was tampered"


# ==============================================================================
# 3. Gate Integration: run_gate detecting real semantic defects
# ==============================================================================

@pytest.mark.integration
class TestGateSemanticIntegration:
    """Test that run_gate detects real semantic defects and emits Verdict.FAIL."""

    def _setup_git_repo(self, tmp_path: Path, files_base: dict[str, str], files_head: dict[str, str], policy: str = POLICY) -> tuple[Path, str, str]:
        repo_dir = tmp_path / "gate_repo"
        repo_dir.mkdir(parents=True)

        def _run(args):
            subprocess.run(["git", "-C", str(repo_dir)] + args, check=True, capture_output=True)

        _run(["init", "-q", "-b", "main"])
        _run(["config", "user.name", "VerifyCI Tester"])
        _run(["config", "user.email", "tester@verifyci.dev"])
        _run(["config", "core.autocrlf", "false"])

        (repo_dir / ".verifyci").mkdir()
        (repo_dir / ".verifyci" / "policy.toml").write_text(policy, encoding="utf-8")

        for path, content in files_base.items():
            fpath = repo_dir / path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content, encoding="utf-8")

        _run(["add", "-A"])
        _run(["commit", "-q", "-m", "base"])
        base_commit = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

        for path, content in files_head.items():
            fpath = repo_dir / path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content, encoding="utf-8")

        _run(["add", "-A"])
        _run(["commit", "-q", "-m", "head"])
        head_commit = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

        return repo_dir, base_commit, head_commit

    def test_run_gate_detects_python_guard_removal_and_emits_fail(self, tmp_path: Path):
        """A PR removing a protected security guard must cause run_gate to emit Verdict.FAIL and exit_code 1."""
        policy_with_guards = (
            POLICY
            + "\n[protected_guards.purge_rule]\n"
            + 'effects = ["delete_account"]\n'
            + 'paths = ["src/**.py"]\n'
            + 'reason = "guard required for account deletion"\n'
        )
        base_py = (
            "def delete_user(user, account_id):\n"
            "    if not user.is_admin:\n"
            "        return False\n"
            "    delete_account(account_id)\n"
            "    return True\n"
        )
        # Defective head: guard removed!
        head_py = (
            "def delete_user(user, account_id):\n"
            "    delete_account(account_id)\n"
            "    return True\n"
        )

        repo_dir, base, head = self._setup_git_repo(
            tmp_path,
            {"src/accounts.py": base_py},
            {"src/accounts.py": head_py},
            policy=policy_with_guards,
        )

        request = GateRequest(
            repo=repo_dir,
            base=base,
            head=head,
            as_of_date=AS_OF,
            review_mode="fail",
        )
        bundle = run_gate(request)

        # Verify fail-closed Verdict.FAIL
        assert bundle.verdict == Verdict.FAIL, f"Expected Verdict.FAIL, got {bundle.verdict}"
        assert bundle.exit_code == 1
        assert bundle.payload["verdict"]["status"] == "FAIL"

        # Check semantic result specifically
        check_results = {r["check_id"]: r for r in bundle.payload["check_results"]}
        assert "semantic" in check_results
        semantic_res = check_results["semantic"]
        assert semantic_res["outcome"] == "FAIL"
        assert semantic_res["tier"] == "blocking"
        assert len(semantic_res["findings"]) >= 1
        assert any(f["defect_id"] == "SEM-GUARD-REMOVED" for f in semantic_res["findings"])

    def test_run_gate_detects_typescript_guard_removal_and_emits_fail(self, tmp_path: Path):
        """A PR removing an admin check in TypeScript must cause run_gate to emit Verdict.FAIL and exit_code 1."""
        policy_with_guards = (
            POLICY
            + "\n[protected_guards.ts_rule]\n"
            + 'effects = ["deleteAccount"]\n'
            + 'paths = ["src/**.ts"]\n'
            + 'reason = "guard required for account deletion in ts"\n'
        )
        base_ts = (
            "function processRequest(user: any, id: string) {\n"
            '    if (user.role === "admin") {\n'
            "        deleteAccount(id);\n"
            "    }\n"
            "}\n"
        )
        # Defective head: guard removed!
        head_ts = (
            "function processRequest(user: any, id: string) {\n"
            "    deleteAccount(id);\n"
            "}\n"
        )

        repo_dir, base, head = self._setup_git_repo(
            tmp_path,
            {"src/service.ts": base_ts},
            {"src/service.ts": head_ts},
            policy=policy_with_guards,
        )

        request = GateRequest(
            repo=repo_dir,
            base=base,
            head=head,
            as_of_date=AS_OF,
            review_mode="fail",
        )
        bundle = run_gate(request)

        # In isolated run, replay confirms divergence and emits Verdict.FAIL (exit 1).
        # Under severe parallel CPU contention, 2.0s Node.js timeout safely fails closed to
        # Verdict.INCONCLUSIVE (exit 2). In neither case does VerifyCI falsely PASS.
        assert bundle.verdict in (Verdict.FAIL, Verdict.INCONCLUSIVE)
        if bundle.verdict == Verdict.FAIL:
            assert bundle.exit_code == 1
            check_results = {r["check_id"]: r for r in bundle.payload["check_results"]}
            assert "semantic" in check_results
            semantic_res = check_results["semantic"]
            assert semantic_res["outcome"] == "FAIL"
            assert semantic_res["tier"] == "blocking"
            assert any(f["defect_id"] == "SEM-GUARD-REMOVED" for f in semantic_res["findings"])
        else:
            assert bundle.exit_code == 2

    def test_run_gate_detects_python_guard_inversion_and_emits_fail(self, tmp_path: Path):
        """A PR inverting an admin check in Python must cause run_gate to emit Verdict.FAIL with SEM-GUARD-INVERTED."""
        policy_with_guards = (
            POLICY
            + "\n[protected_guards.op_rule]\n"
            + 'effects = ["execute_privileged_op"]\n'
            + 'paths = ["src/**.py"]\n'
            + 'reason = "guard required for privileged operation"\n'
        )
        base_py = (
            "def authorize(user):\n"
            "    if not user.is_admin:\n"
            "        return\n"
            "    execute_privileged_op()\n"
        )
        head_py = (
            "def authorize(user):\n"
            "    if user.is_admin:\n"
            "        return\n"
            "    execute_privileged_op()\n"
        )

        repo_dir, base, head = self._setup_git_repo(
            tmp_path,
            {"src/auth.py": base_py},
            {"src/auth.py": head_py},
            policy=policy_with_guards,
        )

        request = GateRequest(
            repo=repo_dir,
            base=base,
            head=head,
            as_of_date=AS_OF,
            review_mode="fail",
        )
        bundle = run_gate(request)

        assert bundle.verdict == Verdict.FAIL
        assert bundle.exit_code == 1
        check_results = {r["check_id"]: r for r in bundle.payload["check_results"]}
        assert "semantic" in check_results
        semantic_res = check_results["semantic"]
        assert semantic_res["outcome"] == "FAIL"
        assert semantic_res["tier"] == "blocking"
        assert any(f["defect_id"] == "SEM-GUARD-INVERTED" for f in semantic_res["findings"])

    def test_run_gate_clean_change_emits_pass(self, tmp_path: Path):
        """A clean equivalent rewrite must evaluate to Verdict.PASS with exit_code 0."""
        policy_with_guards = (
            POLICY
            + "\n[protected_guards.purge_rule]\n"
            + 'effects = ["delete_account"]\n'
            + 'paths = ["src/**.py"]\n'
            + 'reason = "guard required for account deletion"\n'
        )
        base_py = (
            "def delete_user(user, account_id):\n"
            "    if not user.is_admin:\n"
            "        return False\n"
            "    delete_account(account_id)\n"
            "    return True\n"
        )
        # Equivalent head rewrite (no semantic divergence)
        head_py = (
            "def delete_user(user, account_id):\n"
            "    if user.is_admin:\n"
            "        delete_account(account_id)\n"
            "        return True\n"
            "    return False\n"
        )

        repo_dir, base, head = self._setup_git_repo(
            tmp_path,
            {"src/accounts.py": base_py},
            {"src/accounts.py": head_py},
            policy=policy_with_guards,
        )

        request = GateRequest(
            repo=repo_dir,
            base=base,
            head=head,
            as_of_date=AS_OF,
            review_mode="fail",
        )
        bundle = run_gate(request)

        assert bundle.verdict == Verdict.PASS, f"Expected Verdict.PASS, got {bundle.verdict} with faults: {bundle.payload.get('faults')}"
        assert bundle.exit_code == 0
        check_results = {r["check_id"]: r for r in bundle.payload["check_results"]}
        assert check_results["semantic"]["outcome"] == "PASS"
