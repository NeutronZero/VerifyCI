"""Tests for candidate build mode, EvidenceBundle safety, waiver diagnostics, and payload deduplication."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

from verifyci.cli import main
from verifyci.contracts.model import (
    CheckResult,
    Coverage,
    Disposition,
    Evidence,
    EvidenceBundle,
    EvidenceKind,
    Finding,
    Outcome,
    Tier,
    Verdict,
    VerdictResult,
    WitnessLevel,
)
from verifyci.evidence.bundle import build_payload, toolchain_fingerprint
from verifyci.evidence.canonical import payload_hash
from verifyci.gate.orchestrator import GateRequest, run_gate
from verifyci.gate.policy import parse_policy_bytes
from verifyci.gate.verdict import apply_waivers

POLICY = '[gate]\ntarget_drift = "record"\n'
AS_OF = "2026-10-21"

_GIT_ENV = os.environ.copy()
_GIT_ENV.update(
    {
        "GIT_AUTHOR_NAME": "VerifyCI Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "VerifyCI Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        env=_GIT_ENV,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr or result.stdout}")
    return result.stdout.strip()


def _repo(tmp_path: Path, files: dict[str, str | None], policy: str = POLICY) -> tuple[Path, str]:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    with open(root / ".git" / "config", "a", encoding="utf-8") as f:
        f.write("\n[core]\n\tautocrlf = false\n\tsafecrlf = false\n")
    (root / ".verifyci").mkdir()
    (root / ".verifyci" / "policy.toml").write_text(policy, encoding="utf-8", newline="\n")
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            continue
        target.write_text(content, encoding="utf-8", newline="\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    return root, _git(root, "rev-parse", "HEAD")


def _commit(root: Path, files: dict[str, str | None], message: str = "head") -> str:
    for path, content in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if content is None:
            target.unlink(missing_ok=True)
        else:
            target.write_text(content, encoding="utf-8", newline="\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def test_candidate_build_returns_inconclusive_without_release_evidence(tmp_path, monkeypatch):
    """vc gate --candidate-build returns INCONCLUSIVE (exit 2) when release evidence is absent."""
    # Ensure release validation fails (simulating local unvalidated build)
    from verifyci.gate import orchestrator

    monkeypatch.setattr(
        orchestrator,
        "verify_release_validation_evidence",
        lambda *args, **kwargs: (False, "local candidate build without release attestation"),
    )

    root, base = _repo(tmp_path, {"app.py": "def foo(): pass\n"})
    head = _commit(root, {"app.py": "def foo(): return 42\n"})

    # 1. Standard run without --candidate-build yields ERROR (exit 3)
    standard_bundle = run_gate(
        GateRequest(
            repo=root,
            base=base,
            head=head,
            as_of_date=AS_OF,
            candidate_build=False,
        )
    )
    assert standard_bundle.verdict == Verdict.ERROR
    assert standard_bundle.exit_code == 3
    assert "check_not_validated" in standard_bundle.payload["verdict"]["fault_reason_codes"]

    # 2. Candidate build run yields INCONCLUSIVE (exit 2)
    candidate_bundle = run_gate(
        GateRequest(
            repo=root,
            base=base,
            head=head,
            as_of_date=AS_OF,
            candidate_build=True,
        )
    )
    assert candidate_bundle.verdict == Verdict.INCONCLUSIVE
    assert candidate_bundle.exit_code == 2
    assert "candidate_build_unvalidated" in candidate_bundle.payload["verdict"]["reason_codes"]
    assert "check_not_validated" not in candidate_bundle.payload["verdict"]["reason_codes"]
    assert not candidate_bundle.payload["verdict"]["fault_reason_codes"]
    diag = next(
        d for d in candidate_bundle.payload["diagnostics"] if d["code"] == "candidate_build_unvalidated"
    )
    assert "local candidate build" in diag["detail"]

    # 3. CLI invocation via main() with --candidate-build flag
    output_path = tmp_path / "out.json"
    cli_exit = main(
        [
            "gate",
            "--repo",
            str(root),
            "--base",
            base,
            "--head",
            head,
            "--candidate-build",
            "--as-of",
            AS_OF,
            "--format",
            "json",
            "--output",
            str(output_path),
        ]
    )
    assert cli_exit == 2
    cli_bundle_data = json.loads(output_path.read_text(encoding="utf-8"))
    assert cli_bundle_data["payload"]["verdict"]["status"] == "INCONCLUSIVE"
    assert cli_bundle_data["payload"]["verdict"]["exit_code"] == 2
    assert "candidate_build_unvalidated" in cli_bundle_data["payload"]["verdict"]["reason_codes"]


def test_candidate_build_yields_fail_when_blocking_findings_exist(tmp_path, monkeypatch):
    """When blocking findings exist, --candidate-build returns FAIL (exit 1) rather than INCONCLUSIVE."""
    from verifyci.gate import orchestrator

    monkeypatch.setattr(
        orchestrator,
        "verify_release_validation_evidence",
        lambda *args, **kwargs: (False, "absent"),
    )

    policy = POLICY + '[deny_changes.core]\npaths = ["src/**"]\nreason = "deny"\n'
    root, base = _repo(tmp_path, {"src/app.py": "x = 1\n"}, policy=policy)
    head = _commit(root, {"src/app.py": "x = 2\n"})

    bundle = run_gate(
        GateRequest(
            repo=root,
            base=base,
            head=head,
            as_of_date=AS_OF,
            candidate_build=True,
        )
    )
    assert bundle.verdict == Verdict.FAIL
    assert bundle.exit_code == 1
    assert "candidate_build_unvalidated" in bundle.payload["verdict"]["reason_codes"]
    assert "policy_prohibited" in bundle.payload["verdict"]["reason_codes"]


def test_apply_waivers_preserves_distinct_diagnostics_for_multiple_findings():
    """apply_waivers preserves separate diagnostics for multiple distinct findings sharing a waiver rule."""
    fp = "sha256:" + "a" * 64
    raw_policy = (
        POLICY
        + "[waivers.w1]\n"
        + 'check = "contract"\n'
        + 'defect_id = "CTR-CALL-INCOMPATIBLE"\n'
        + f'fingerprint = "{fp}"\n'
        + 'reason = "legacy deprecated call"\n'
        + 'approved_by = "@org/reviewers"\n'
        + 'created = "2020-01-01"\n'
        + 'expires = "2021-01-01"\n'  # Expired as of 2026-10-21 -> stale waiver
    )
    policy = parse_policy_bytes(
        raw_policy.encode("utf-8"), source=".verifyci/policy.toml", blob_hash="sha256:1111"
    )

    evidence = Evidence(kind=EvidenceKind.CALL_SITE, payload={"detail": "call site"})
    finding1 = Finding(
        tier=Tier.BLOCKING,
        defect_id="CTR-CALL-INCOMPATIBLE",
        reason_code="call_incompatible",
        defect_semantics_version=1,
        subject={"path": "src/pkg/client.py", "line": 42, "check_id": "contract"},
        premises={},
        evidence=evidence,
        witness_level=WitnessLevel.SOURCE,
        message="signature mismatch",
        disposition=Disposition.OPEN,
        fingerprint=fp,
    )
    finding2 = Finding(
        tier=Tier.BLOCKING,
        defect_id="CTR-CALL-INCOMPATIBLE",
        reason_code="call_incompatible",
        defect_semantics_version=1,
        subject={"path": "src/pkg/other.py", "line": 105, "check_id": "contract"},
        premises={},
        evidence=evidence,
        witness_level=WitnessLevel.SOURCE,
        message="signature mismatch in caller",
        disposition=Disposition.OPEN,
        fingerprint=fp,
    )
    # Finding 3 is an identical repeat of finding 1 to verify exact duplicate suppression
    finding3 = Finding(
        tier=Tier.BLOCKING,
        defect_id="CTR-CALL-INCOMPATIBLE",
        reason_code="call_incompatible",
        defect_semantics_version=1,
        subject={"path": "src/pkg/client.py", "line": 42, "check_id": "contract"},
        premises={},
        evidence=evidence,
        witness_level=WitnessLevel.SOURCE,
        message="signature mismatch",
        disposition=Disposition.OPEN,
        fingerprint=fp,
    )

    check_res = CheckResult(
        check_id="contract",
        check_version="v3",
        tier=Tier.BLOCKING,
        maturity="v3",
        outcome=Outcome.FAIL,
        coverage=Coverage.COMPLETE,
        reason_codes=("call_incompatible",),
        findings=(finding1, finding2, finding3),
    )

    _, _, reviews, diagnostics = apply_waivers([check_res], policy, as_of_date=AS_OF)

    assert "waiver_review" in reviews
    # Two distinct findings on different paths/lines should produce 2 distinct diagnostics
    stale_diags = [d for d in diagnostics if d["code"] == "stale_waiver_present"]
    assert len(stale_diags) == 2

    paths_in_diags = {d.get("path") for d in stale_diags}
    lines_in_diags = {d.get("line") for d in stale_diags}
    assert paths_in_diags == {"src/pkg/client.py", "src/pkg/other.py"}
    assert lines_in_diags == {42, 105}


def test_evidence_bundle_verdict_fails_safely_on_corrupt_payloads():
    """EvidenceBundle.verdict and exit_code fail safely to ERROR and 3 on malformed/corrupted payloads."""
    # 1. Missing verdict dict
    b1 = EvidenceBundle(payload={}, envelope={})
    assert b1.verdict == Verdict.ERROR
    assert b1.exit_code == 3

    # 2. None verdict
    b2 = EvidenceBundle(payload={"verdict": None}, envelope={})
    assert b2.verdict == Verdict.ERROR
    assert b2.exit_code == 3

    # 3. Missing status in verdict dict
    b3 = EvidenceBundle(payload={"verdict": {"exit_code": 0}}, envelope={})
    assert b3.verdict == Verdict.ERROR
    assert b3.exit_code == 0

    # 4. Unknown/malformed status string
    b4 = EvidenceBundle(payload={"verdict": {"status": "CORRUPT_UNKNOWN_VERDICT"}}, envelope={})
    assert b4.verdict == Verdict.ERROR
    assert b4.exit_code == 3

    # 5. Non-mapping payload
    b5 = EvidenceBundle(payload="string_not_dict", envelope={})  # type: ignore[arg-type]
    assert b5.verdict == Verdict.ERROR
    assert b5.exit_code == 3

    # 6. Valid payload returns correct verdict and exit_code
    b6 = EvidenceBundle(payload={"verdict": {"status": "PASS", "exit_code": 0}}, envelope={})
    assert b6.verdict == Verdict.PASS
    assert b6.exit_code == 0

    # 7. Valid payload with non-integer exit_code falls back safely
    b7 = EvidenceBundle(payload={"verdict": {"status": "PASS", "exit_code": "not_int"}}, envelope={})
    assert b7.verdict == Verdict.PASS
    assert b7.exit_code == 0


def test_build_payload_deduplication_and_canonical_hashing():
    """build_payload deduplicates redundant mappings while preserving exact canonical hashing."""
    toolchain = toolchain_fingerprint(git_version="git version 2.45.0")
    diag_dup = {"code": "review_reason", "reason_code": "policy_change_review"}
    assumption_dup = {"id": "single_line_records", "detail": "deterministic"}

    payload1 = build_payload(
        inputs={"target_ref": "main"},
        scope={"changed_files": 1},
        check_results=[],
        findings=[],
        waivers=[],
        accepted_gaps=[],
        diagnostics=[diag_dup, diag_dup, diag_dup],
        assumptions=[assumption_dup, assumption_dup],
        excluded_scope=[],
        verdict=VerdictResult(status=Verdict.PASS, exit_code=0, blocking_findings_present=False),
        toolchain=toolchain,
        policy={"effective_policy_hash": "sha256:123"},
        gate_integrity={"policy_changed": False},
    )

    # Deduplication checks
    assert len(payload1["diagnostics"]) == 1
    assert payload1["diagnostics"][0] == diag_dup
    assert len(payload1["assumptions"]) == 1
    assert payload1["assumptions"][0] == assumption_dup

    # Same payload built without duplicates produces the identical payload hash
    payload2 = build_payload(
        inputs={"target_ref": "main"},
        scope={"changed_files": 1},
        check_results=[],
        findings=[],
        waivers=[],
        accepted_gaps=[],
        diagnostics=[diag_dup],
        assumptions=[assumption_dup],
        excluded_scope=[],
        verdict=VerdictResult(status=Verdict.PASS, exit_code=0, blocking_findings_present=False),
        toolchain=toolchain,
        policy={"effective_policy_hash": "sha256:123"},
        gate_integrity={"policy_changed": False},
    )

    assert payload_hash(payload1) == payload_hash(payload2)

    # When policy is empty but inputs has policy, policy is preserved from inputs
    payload3 = build_payload(
        inputs={"policy": {"effective_policy_hash": "sha256:456"}},
        scope={},
        check_results=[],
        findings=[],
        waivers=[],
        accepted_gaps=[],
        diagnostics=[],
        assumptions=[],
        excluded_scope=[],
        verdict=VerdictResult(status=Verdict.PASS, exit_code=0, blocking_findings_present=False),
        toolchain=toolchain,
        policy={},
        gate_integrity={},
    )
    assert payload3["policy"]["effective_policy_hash"] == "sha256:456"
