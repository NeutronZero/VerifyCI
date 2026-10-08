import time
import uuid

from verifyci.contracts.verification_ir import VerificationReport, VerificationDecision


class PolicyEvaluator:
    def evaluate(self, report: VerificationReport, policy) -> VerificationDecision:
        # INCONCLUSIVE means "no deterministic checker ran" — never "a
        # checker ran and rejected". Rejection is FAIL (below).
        # Only the consulted fields are validated: an unrecognized
        # on_failure used to fall through past both branches, turning a
        # real rejection into whatever the inconclusive path said
        # (including PASS under warn). on_human_review is never read;
        # validating it would break existing constructions for nothing.
        if getattr(policy, "on_failure", None) not in ("block",):
            raise ValueError(f"unknown on_failure: {policy.on_failure!r}")
        if getattr(policy, "on_inconclusive", None) not in ("human_review", "warn"):
            raise ValueError(f"unknown on_inconclusive: {policy.on_inconclusive!r}")

        # A report with no checks is not evidence of safety.  It is an
        # unevaluated request and must never inherit all([]) == True.
        if not report.checks:
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="INCONCLUSIVE",
                policy_id=policy.policy_id,
                rationale=(
                    "no_deterministic_checker_executed"
                    if policy.require_deterministic_checker else "no_checks_executed"
                ),
                timestamp=time.time(),
            )

        if policy.require_deterministic_checker and not _executed_deterministic(report):
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="INCONCLUSIVE",
                policy_id=policy.policy_id,
                rationale="no_deterministic_checker_executed",
                timestamp=time.time(),
            )

        # A PASS is only meaningful when every passed check is established
        # and, when it carries a certificate, that certificate is verified.
        # Missing/incomplete/unverified evidence can never launder into PASS.
        if all(check.passed for check in report.checks):
            if any(not _check_pass_is_established(check) for check in report.checks):
                return VerificationDecision(
                    decision_id=str(uuid.uuid4()),
                    report_id=report.report_id,
                    status="INCONCLUSIVE",
                    policy_id=policy.policy_id,
                    rationale="unestablished_or_unverified_checks",
                    timestamp=time.time(),
                )
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="PASS",
                policy_id=policy.policy_id,
                rationale="all_checks_passed_behavior_not_verified",
                timestamp=time.time(),
            )

        blocking = [c for c in report.checks if c.blocking and not c.passed]
        rejections = [c for c in blocking if not _is_inability(c)]
        if rejections:
            if policy.on_failure == "block":
                return VerificationDecision(
                    decision_id=str(uuid.uuid4()),
                    report_id=report.report_id,
                    status="FAIL",
                    policy_id=policy.policy_id,
                    rationale="blocking_check_failed",
                    timestamp=time.time(),
                )

        if blocking and not rejections:
            # Checks ran, but none established anything and none rejected:
            # ungroundable diff, not a failed one.
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="INCONCLUSIVE",
                policy_id=policy.policy_id,
                rationale="checks_ran_but_nothing_established",
                timestamp=time.time(),
            )

        if policy.on_inconclusive == "human_review":
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="HUMAN_REVIEW",
                policy_id=policy.policy_id,
                rationale="non_blocking_failures",
                timestamp=time.time(),
            )
        elif policy.on_inconclusive == "warn":
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="PASS",
                policy_id=policy.policy_id,
                rationale="non_blocking_failures_but_warn",
                timestamp=time.time(),
            )

        return VerificationDecision(
            decision_id=str(uuid.uuid4()),
            report_id=report.report_id,
            status="HUMAN_REVIEW",
            policy_id=policy.policy_id,
            rationale="default",
            timestamp=time.time(),
        )


def _is_inability(check) -> bool:
    """Inability (route to INCONCLUSIVE), as opposed to rejection (FAIL).

    A failed check that ran against established content and concluded
    rejection (certificate conclusion "fail") is a real rejection:
    `certificate_verified` requires every check to pass, so a
    rejecting certificate is unverified by construction — reading that
    as inability collapsed every code-path rejection (guard removal,
    fabricated deletion, invalid config) into INCONCLUSIVE. Only an
    inconclusive conclusion (nothing grounded) or an unestablished
    check (ran against nothing) declines to INCONCLUSIVE.
    """
    cert = getattr(check, "certificate", None)
    if cert is None:
        return not getattr(check, "established", True)
    if getattr(cert, "certificate_verified", False):
        return False
    if getattr(getattr(cert, "conclusion", None), "result", "") == "fail":
        return not getattr(check, "established", True)
    return True


def _executed_deterministic(report: VerificationReport) -> bool:
    """True when at least one deterministic checker ran, regardless of its
    verdict. LLM-only checks (deterministic=False, no certificate) don't count."""
    for check in report.checks:
        if check.certificate is not None:
            return True
        if getattr(check, "deterministic", True):
            return True
    return False


def _check_pass_is_established(check) -> bool:
    """Return True only when a passed check has grounded, verified evidence."""
    if not getattr(check, "established", True):
        return False
    certificate = getattr(check, "certificate", None)
    if certificate is not None and not getattr(certificate, "certificate_verified", False):
        return False
    return True
