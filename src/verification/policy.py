import time
import uuid

from src.contracts.verification_ir import VerificationReport, VerificationDecision


class PolicyEvaluator:
    def evaluate(self, report: VerificationReport, policy) -> VerificationDecision:
        if policy.require_deterministic_checker:
            has_deterministic = any(
                check.certificate and check.certificate.certificate_verified
                for check in report.checks
            )
            if not has_deterministic:
                return VerificationDecision(
                    decision_id=str(uuid.uuid4()),
                    report_id=report.report_id,
                    status="INCONCLUSIVE",
                    policy_id=policy.policy_id,
                    rationale="no_deterministic_checker",
                    timestamp=time.time(),
                )

        if all(check.passed for check in report.checks):
            return VerificationDecision(
                decision_id=str(uuid.uuid4()),
                report_id=report.report_id,
                status="PASS",
                policy_id=policy.policy_id,
                rationale="all_checks_passed",
                timestamp=time.time(),
            )

        if any(check.blocking and not check.passed for check in report.checks):
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
