"""Verdict, Severity, and Finding models for VerifyCI."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class VerificationVerdict(str, Enum):
    """The canonical three-state verdict ladder.

    Precedence: FAIL > INCONCLUSIVE > PASS.
    """

    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    PASS = "PASS"


class Severity(str, Enum):
    """Severity levels for verification findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingReason(str, Enum):
    """Normalized finding reason codes.

    UNGROUNDED is a reason code, not a verdict.
    """

    UNGROUNDED_REMOVAL = "UNGROUNDED_REMOVAL"
    FABRICATED_REMOVAL = "FABRICATED_REMOVAL"
    SECRET_LEAK = "SECRET_LEAK"
    DANGEROUS_CALL = "DANGEROUS_CALL"
    UNRESOLVED_IMPORT = "UNRESOLVED_IMPORT"
    SEMANTIC_DIVERGENCE = "SEMANTIC_DIVERGENCE"
    SMT_TIMEOUT = "SMT_TIMEOUT"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    AST_SYNTAX_ERROR = "AST_SYNTAX_ERROR"
    CONCURRENCY_VIOLATION = "CONCURRENCY_VIOLATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"


@dataclass(frozen=True)
class VerificationFinding:
    """An individual finding emitted during verification."""

    finding_id: str
    rule_id: str
    severity: Severity
    verdict: VerificationVerdict
    reason: FindingReason
    message: str
    file_path: str
    start_line: int = 1
    end_line: int = 1
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to standard dictionary for serialization."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "verdict": self.verdict.value,
            "reason": self.reason.value,
            "message": self.message,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "details": dict(self.details),
        }


def derive_verdict(
    findings: Sequence[VerificationFinding],
) -> tuple[VerificationVerdict, str]:
    """Derive the single authoritative verdict from a sequence of findings.

    Enforces fail-closed verdict precedence:
    FAIL > INCONCLUSIVE > PASS.

    A confirmed failure takes precedence over any inconclusive result and is
    never downgraded.
    """
    fail_findings = [f for f in findings if f.verdict == VerificationVerdict.FAIL]
    if fail_findings:
        reasons = sorted({f.reason.value for f in fail_findings})
        sample_msgs = "; ".join(f.message for f in fail_findings[:3])
        return (
            VerificationVerdict.FAIL,
            f"Blocking violations ({len(fail_findings)}) [{', '.join(reasons)}]: {sample_msgs}",
        )

    inconclusive_findings = [
        f for f in findings if f.verdict == VerificationVerdict.INCONCLUSIVE
    ]
    if inconclusive_findings:
        reasons = sorted({f.reason.value for f in inconclusive_findings})
        sample_msgs = "; ".join(f.message for f in inconclusive_findings[:3])
        return (
            VerificationVerdict.INCONCLUSIVE,
            f"Verification inconclusive ({len(inconclusive_findings)}) [{', '.join(reasons)}]: {sample_msgs}",
        )

    return (
        VerificationVerdict.PASS,
        "All verified contracts and invariant gates satisfied in diff",
    )
