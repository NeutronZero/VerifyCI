"""The decision table as data.

This test pins that the code implements the published table — it cannot
prove the table itself is right. Table-correctness evidence lives outside
the suite: the real-repo distributions (Flask 4 PASS / 1 INCONCLUSIVE,
secrets FAIL, ghost-file INCONCLUSIVE in benchmarks/real_repo.md). A table
copied into code and tested against itself would be circular one level up;
the distributions are the external authority. If a real distribution ever
contradicts a row below, the table is wrong, not the world.
"""
import dataclasses

from src.contracts.verification_ir import (
    BlastRadiusResult, CheckResult, VerificationDecision, VerificationPolicy,
    VerificationReport,
)
from src.verification.policy import PolicyEvaluator


def _policy():
    return VerificationPolicy(
        policy_id="pol1", on_failure="block", on_inconclusive="human_review",
        on_human_review="block", require_deterministic_checker=True,
    )


def _certified(verified: bool):
    from src.contracts.verification_ir import (
        Certificate, Conclusion, ExecutionTrace, FileEvidence, Premise,
    )
    return Certificate(
        certificate_id="c", premises=[], evidence=[], execution_traces=[],
        conclusion=Conclusion(result="x", reasoning="x"), confidence=1.0,
        generated_by="t", checked_by=[], verification_method="t",
        certificate_verified=verified, timestamp=0.0,
    )


def _check(passed=True, blocking=True, certificate=None, established=True, deterministic=True):
    return CheckResult(
        check_id="chk", passed=passed, score=1.0, evidence=[],
        explanation="t", blocking=blocking, certificate=certificate,
        deterministic=deterministic, established=established,
    )


def _report(checks):
    return VerificationReport(
        report_id="r", task_id="t", policy_id="pol1", checks=checks,
        blast_radius=BlastRadiusResult(
            affected_callers=[], affected_callees=[], test_coverage_gap=[],
            risk_score=0.0, dependency_impact=[], vulnerability_impact=[]),
        timestamp=0.0,
    )


def _decide(checks) -> VerificationDecision:
    return PolicyEvaluator().evaluate(_report(checks), _policy())


def test_table_no_checker_ran():
    d = _decide([])
    assert (d.status, d.rationale) == ("INCONCLUSIVE", "no_deterministic_checker_executed")


def test_table_rejection():
    d = _decide([_check(passed=False, blocking=True)])
    assert (d.status, d.rationale) == ("FAIL", "blocking_check_failed")


def test_table_inability():
    d = _decide([_check(passed=False, blocking=True, certificate=_certified(False))])
    assert (d.status, d.rationale) == ("INCONCLUSIVE", "checks_ran_but_nothing_established")


def test_table_all_pass():
    d = _decide([_check(passed=True), _check(passed=True, blocking=False)])
    assert (d.status, d.rationale) == ("PASS", "all_checks_passed_behavior_not_verified")


def test_table_nonblocking_only():
    d = _decide([_check(passed=True), _check(passed=False, blocking=False)])
    assert (d.status, d.rationale) == ("HUMAN_REVIEW", "non_blocking_failures")


def test_table_unestablished_pass_deflects():
    d = _decide([_check(passed=True),
                 dataclasses.replace(_check(passed=True), established=False)])
    assert (d.status, d.rationale) == ("INCONCLUSIVE", "unestablished_blocking_checks")
