"""Contract tests for verdict precedence and finding reasons."""

from __future__ import annotations

import pytest

from verifyci.contracts.capabilities import (
    Capability,
    CapabilityDeclaration,
    ExecutionStatus,
)
from verifyci.contracts.verdict import (
    FindingReason,
    Severity,
    VerificationFinding,
    VerificationVerdict,
    derive_verdict,
)


def _make_finding(
    verdict: VerificationVerdict,
    reason: FindingReason,
    rule_id: str = "VC-TEST",
    message: str = "test message",
) -> VerificationFinding:
    return VerificationFinding(
        finding_id=f"test:{verdict.value}:{reason.value}",
        rule_id=rule_id,
        severity=Severity.HIGH,
        verdict=verdict,
        reason=reason,
        message=message,
        file_path="src/app.py",
    )


def test_verdict_precedence_fail_over_inconclusive() -> None:
    findings = [
        _make_finding(VerificationVerdict.INCONCLUSIVE, FindingReason.UNGROUNDED_REMOVAL),
        _make_finding(VerificationVerdict.FAIL, FindingReason.SECRET_LEAK),
    ]
    verdict, rationale = derive_verdict(findings)
    assert verdict == VerificationVerdict.FAIL
    assert "SECRET_LEAK" in rationale


def test_verdict_precedence_inconclusive_over_pass() -> None:
    findings = [
        _make_finding(VerificationVerdict.INCONCLUSIVE, FindingReason.UNRESOLVED_IMPORT),
    ]
    verdict, rationale = derive_verdict(findings)
    assert verdict == VerificationVerdict.INCONCLUSIVE
    assert "UNRESOLVED_IMPORT" in rationale


def test_verdict_empty_findings_is_pass() -> None:
    verdict, rationale = derive_verdict([])
    assert verdict == VerificationVerdict.PASS
    assert "satisfied" in rationale


def test_required_capability_incomplete_yields_inconclusive() -> None:
    cap = CapabilityDeclaration(
        capability=Capability.SYMBOLIC_EQUIVALENCE,
        required=True,
        status=ExecutionStatus.UNAVAILABLE,
        detail="Z3 solver not installed",
    )
    finding = cap.evaluate_finding()
    assert finding is not None
    assert finding.verdict == VerificationVerdict.INCONCLUSIVE
    assert finding.reason == FindingReason.CAPABILITY_UNAVAILABLE


def test_optional_capability_incomplete_yields_no_finding() -> None:
    cap = CapabilityDeclaration(
        capability=Capability.SYMBOLIC_EQUIVALENCE,
        required=False,
        status=ExecutionStatus.UNAVAILABLE,
    )
    assert cap.evaluate_finding() is None
