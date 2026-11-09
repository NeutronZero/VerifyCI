"""Regression tests for Gate Orchestrator, Packaging, and Release Trust fixes."""

from __future__ import annotations

from pathlib import Path
import sys
import pytest

from verifyci import __version__
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    Disposition,
    Evidence,
    EvidenceKind,
    Finding,
    Outcome,
    Tier,
    Verdict,
    WitnessLevel,
)
from verifyci.contracts.release_validation import (
    _CRITICAL_IMPLEMENTATION_FILES,
    get_verifyci_root,
    verify_release_validation_evidence,
)
from verifyci.gate.orchestrator import GateRequest, run_gate
from verifyci.gate.verdict import aggregate


def test_invalid_repo_path_yields_invalid_repository_fatal_bundle(tmp_path: Path) -> None:
    """Test that a non-existent or invalid repository path returns fatal bundle with invalid_repository fault and exit code 3."""
    # 1. Non-existent path
    non_existent = tmp_path / "does_not_exist"
    req1 = GateRequest(repo=non_existent, base="main")
    bundle1 = run_gate(req1)

    assert bundle1.exit_code == 3
    assert bundle1.verdict == Verdict.ERROR
    assert bundle1.payload["verdict"]["status"] == "ERROR"
    assert "invalid_repository" in bundle1.payload["verdict"]["reason_codes"]
    assert any(d.get("code") == "invalid_repository" for d in bundle1.payload["diagnostics"])

    # 2. Existing directory but not a git repo
    empty_dir = tmp_path / "not_a_git_repo"
    empty_dir.mkdir()
    req2 = GateRequest(repo=empty_dir, base="main")
    bundle2 = run_gate(req2)

    assert bundle2.exit_code == 3
    assert bundle2.verdict == Verdict.ERROR
    assert bundle2.payload["verdict"]["status"] == "ERROR"
    assert "invalid_repository" in bundle2.payload["verdict"]["reason_codes"]
    assert any(d.get("code") == "invalid_repository" for d in bundle2.payload["diagnostics"])


def test_blocking_findings_present_false_when_error_findings_are_waived() -> None:
    """Test that blocking_findings_present is False when findings on ERROR are waived."""
    finding_waived = Finding(
        tier=Tier.BLOCKING,
        defect_id="SEC-SECRET",
        reason_code="secret_detected",
        defect_semantics_version=1,
        subject={"path": "src/config.py", "line": 10},
        premises={},
        evidence=Evidence(kind=EvidenceKind.SECRET_VALIDATION, payload={"snippet": "sk_live_1234"}),
        witness_level=WitnessLevel.SOURCE,
        message="secret detected in config",
        disposition=Disposition.WAIVED,
    )

    check_with_waived = CheckResult(
        check_id="security",
        check_version="v3",
        tier=Tier.BLOCKING,
        maturity="v3",
        outcome=Outcome.PASS,
        coverage=Coverage.COMPLETE,
        evaluated_scope={},
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": True},
        applicability_evidence={},
        method="deterministic_pattern_scanner",
        method_version="v3",
        reason_codes=(),
        findings=(finding_waived,),
    )

    # In ERROR state (e.g. from an extra fault or check failure), waived findings
    # must NOT cause blocking_findings_present to be True.
    res = aggregate([check_with_waived], extra_faults={"internal_fault"})
    assert res.status == Verdict.ERROR
    assert res.exit_code == 3
    assert res.blocking_findings_present is False

    # Conversely, when an OPEN finding is present, blocking_findings_present MUST be True.
    finding_open = Finding(
        tier=Tier.BLOCKING,
        defect_id="SEC-SECRET",
        reason_code="secret_detected",
        defect_semantics_version=1,
        subject={"path": "src/config.py", "line": 10},
        premises={},
        evidence=Evidence(kind=EvidenceKind.SECRET_VALIDATION, payload={"snippet": "sk_live_1234"}),
        witness_level=WitnessLevel.SOURCE,
        message="secret detected in config",
        disposition=Disposition.OPEN,
    )
    check_with_open = CheckResult(
        check_id="security",
        check_version="v3",
        tier=Tier.BLOCKING,
        maturity="v3",
        outcome=Outcome.FAIL,
        coverage=Coverage.COMPLETE,
        evaluated_scope={},
        scope_enumeration={"complete": True},
        candidate_discovery={"complete": True},
        applicability_evidence={},
        method="deterministic_pattern_scanner",
        method_version="v3",
        reason_codes=("secret_detected",),
        findings=(finding_open,),
    )
    res_open = aggregate([check_with_open], extra_faults={"internal_fault"})
    assert res_open.status == Verdict.ERROR
    assert res_open.exit_code == 3
    assert res_open.blocking_findings_present is True


def test_get_verifyci_root_behavior(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Test get_verifyci_root fallback, env override, and standard discovery."""
    import verifyci.contracts.release_validation as rv

    # In the real repo, root is discoverable because .git or evidence/ exists
    root = get_verifyci_root()
    assert (root / ".git").exists() or (root / "evidence" / "release" / "release_validation.json").exists()

    # Test explicit environment override VERIFYCI_ROOT when candidate has no .git/evidence
    fake_root = tmp_path / "custom_install_root"
    fake_root.mkdir()
    monkeypatch.setenv("VERIFYCI_ROOT", str(fake_root))

    # Point __file__ to a dummy file located in a non-git directory
    fake_pkg_file = tmp_path / "site-packages" / "verifyci" / "contracts" / "release_validation.py"
    fake_pkg_file.parent.mkdir(parents=True)
    fake_pkg_file.touch()
    monkeypatch.setattr(rv, "__file__", str(fake_pkg_file))

    override_result = get_verifyci_root()
    assert override_result == fake_root


def test_critical_implementation_files_allowlist_coverage() -> None:
    """Test that _CRITICAL_IMPLEMENTATION_FILES contains all required engine paths."""
    critical_paths = {p.as_posix() for p in _CRITICAL_IMPLEMENTATION_FILES}

    # verifyci/scope/entities.py
    assert "verifyci/scope/entities.py" in critical_paths

    # verifyci/index/
    assert "verifyci/index/__init__.py" in critical_paths
    assert "verifyci/index/cache.py" in critical_paths
    assert "verifyci/index/facts.py" in critical_paths
    assert "verifyci/index/provider.py" in critical_paths
    assert "verifyci/index/symbol_index.py" in critical_paths

    # verifyci/evidence/
    assert "verifyci/evidence/__init__.py" in critical_paths
    assert "verifyci/evidence/bundle.py" in critical_paths
    assert "verifyci/evidence/canonical.py" in critical_paths
    assert "verifyci/evidence/sarif.py" in critical_paths

    # docker/worker/
    assert "docker/worker/Dockerfile" in critical_paths
    assert "docker/worker/launch_candidate.py" in critical_paths
    assert "docker/worker/requirements.lock" in critical_paths

    # corpora specs
    assert "corpora/contract/CORPUS_SPEC.md" in critical_paths
    assert "corpora/deletion/CORPUS_SPEC.md" in critical_paths
    assert "corpora/security/CORPUS_SPEC.md" in critical_paths
    assert "corpora/semantic/CORPUS_SPEC.md" in critical_paths


def test_verify_release_validation_evidence_authority_key_restriction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that authority public key cannot be overridden accidentally or in non-test runs."""
    # Passing the old keyword argument directly raises TypeError
    with pytest.raises(TypeError, match="authority_public_key_hex cannot be overridden"):
        verify_release_validation_evidence(authority_public_key_hex="abcdef0123")  # type: ignore[call-arg]

    # In production (when pytest is simulated absent and VERIFYCI_TESTING is unset),
    # passing _authority_public_key_hex fails closed with an error.
    monkeypatch.delitem(sys.modules, "pytest", raising=False)
    monkeypatch.delenv("VERIFYCI_TESTING", raising=False)
    ok, err = verify_release_validation_evidence(_authority_public_key_hex="00" * 32)
    assert ok is False
    assert "unauthorized authority key override" in str(err)


def test_pinned_version_synchronization() -> None:
    """Test that TOOL_VERSION across all release and signing modules synchronizes with verifyci.__version__."""
    from scripts.generate_trusted_attestation import TOOL_VERSION as ATTESTATION_VERSION
    from scripts.standalone_signer import TOOL_VERSION as SIGNER_VERSION
    from verifyci_release_trust.supervisor import TOOL_VERSION as SUPERVISOR_VERSION

    assert __version__ == "3.1.10"
    assert ATTESTATION_VERSION == __version__
    assert SIGNER_VERSION == __version__
    assert SUPERVISOR_VERSION == __version__
