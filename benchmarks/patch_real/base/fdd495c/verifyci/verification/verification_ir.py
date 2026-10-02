import time
import uuid

from verifyci.contracts.verification_ir import (
    VerificationReport, CheckResult, BlastRadiusResult,
)


def build_semi_check(cert, files: list[str], entities: list) -> CheckResult:
    """Build the semi-formal CheckResult, appending a suffix-grounding
    ambiguity note when one diff path matched entities under several stored
    paths. Single shared constructor so the tripwire can't rot in one of
    the three call sites (executor, MCP, CLI)."""
    from verifyci.verification.diffmap import find_ambiguous_files
    explanation = cert.conclusion.reasoning
    ambiguous = find_ambiguous_files(files, entities or [])
    if ambiguous:
        details = ", ".join(f"{f} ({len(p)} paths)" for f, p in sorted(ambiguous.items()))
        explanation = f"{explanation}; suffix-ambiguous grounding: {details}"
    return CheckResult(
        check_id="semi_formal",
        passed=cert.certificate_verified,
        score=cert.confidence,
        evidence=[e.file_path for e in cert.evidence],
        explanation=explanation,
        # The certificate travels with the check so policy can tell
        # inability (unverified cert → INCONCLUSIVE) from rejection
        # (failed check on a verified cert → FAIL). Without it every
        # grounding failure read as a rejection.
        certificate=cert,
    )


def build_verification_report(
    task_id: str,
    policy_id: str,
    checks: list[CheckResult],
    blast_radius: BlastRadiusResult,
) -> VerificationReport:
    return VerificationReport(
        report_id=str(uuid.uuid4()),
        task_id=task_id,
        policy_id=policy_id,
        checks=checks,
        blast_radius=blast_radius,
        timestamp=time.time(),
    )
