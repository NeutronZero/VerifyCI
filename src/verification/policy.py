import time
import uuid

from src.contracts.verification_ir import VerificationReport, VerificationDecision


class PolicyEvaluator:
    def evaluate(self, report: VerificationReport, policy) -> VerificationDecision:
        # INCONCLUSIVE means "no deterministic checker ran" — never "a
        # checker ran and rejected". Rejection is FAIL (below).
        if policy.require_deterministic_checker and not _executed_deterministic(report):
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="INCONCLUSIVE",
                policy_id=policy.policy_id,
                rationale="no_deterministic_checker_executed",
                timestamp=time.time(),
            )

        if all(check.passed for check in report.checks):
            # A pass-on-zero-edges is not a pass-on-500-edges: a blocking
            # check that established nothing deflects to INCONCLUSIVE even
            # when nothing failed. Decided explicitly, not inherited.
            if any(check.blocking and not getattr(check, "established", True)
                   for check in report.checks):
                return VerificationDecision(
                    decision_id=str(uuid.uuid4()),
                    report_id=report.report_id,
                    status="INCONCLUSIVE",
                    policy_id=policy.policy_id,
                    rationale="unestablished_blocking_checks",
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
            elif policy.on_failure == "warn":
                return VerificationDecision(
                    decision_id=str(uuid.uuid4()),
                    report_id=report.report_id,
                    status="PASS",
                    policy_id=policy.policy_id,
                    rationale="blocking_check_failed_but_warn",
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
    """Inability (route to INCONCLUSIVE), as opposed to rejection (FAIL):
    an unverified certificate (ungroundable diff), or a check that ran
    against nothing (established=False, e.g. zero relevant edges)."""
    cert = getattr(check, "certificate", None)
    if cert is not None and not getattr(cert, "certificate_verified", False):
        return True
    return not getattr(check, "established", True)


def _executed_deterministic(report: VerificationReport) -> bool:
    """True when at least one deterministic checker ran, regardless of its
    verdict. LLM-only checks (deterministic=False, no certificate) don't count."""
    for check in report.checks:
        if check.certificate is not None:
            return True
        if getattr(check, "deterministic", True):
            return True
    return False
