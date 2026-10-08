from verifyci.verification.policy import PolicyEvaluator
from verifyci.verification.semi_formal_reason import SemiFormalReasoner
from verifyci.verification.intent_align import evaluate_invariants
from verifyci.verification.evidence_verifier import verify_evidence_coverage
from verifyci.contracts.verification_ir import (
    VerificationReport, CheckResult, VerificationPolicy, BlastRadiusResult,
)
from verifyci.contracts.evidence import EvidencePack, SourceChunk


def make_check(passed=True, blocking=True):
    from verifyci.contracts.verification_ir import Certificate, Premise, FileEvidence, ExecutionTrace, Conclusion
    cert = Certificate(
        certificate_id="cert1",
        premises=[Premise(premise_id="p1", statement="test", source="test")],
        evidence=[FileEvidence(file_path="test.py", line_start=1, line_end=5, snippet="test", source_hash="abc")],
        execution_traces=[ExecutionTrace(trace_id="t1", path=["a", "b"], conditions=[])],
        conclusion=Conclusion(result="pass", reasoning="test"),
        confidence=0.9,
        generated_by="test-model",
        checked_by=["graph_traversal"],
        verification_method="semi_formal_reasoning",
        certificate_verified=True,
        timestamp=0.0,
    )
    return CheckResult(
        check_id="chk1",
        passed=passed,
        score=1.0 if passed else 0.0,
        evidence=[],
        explanation="test",
        blocking=blocking,
        certificate=cert,
    )


def make_report(checks):
    return VerificationReport(
        report_id="rep1",
        task_id="task1",
        policy_id="pol1",
        checks=checks,
        blast_radius=BlastRadiusResult(
            affected_callers=[], affected_callees=[],
            test_coverage_gap=[], risk_score=0.0,
            dependency_impact=[], vulnerability_impact=[],
        ),
        timestamp=0.0,
    )


def test_policy_evaluator_pass():
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    report = make_report([make_check(passed=True)])
    evaluator = PolicyEvaluator()
    decision = evaluator.evaluate(report, policy)
    assert decision.status == "PASS"


def test_policy_evaluator_fail():
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    report = make_report([make_check(passed=False, blocking=True)])
    evaluator = PolicyEvaluator()
    decision = evaluator.evaluate(report, policy)
    assert decision.status == "FAIL"


def test_policy_evaluator_human_review():
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    report = make_report([make_check(passed=False, blocking=False)])
    evaluator = PolicyEvaluator()
    decision = evaluator.evaluate(report, policy)
    assert decision.status == "HUMAN_REVIEW"


def test_policy_failed_check_is_fail_not_inconclusive():
    # Auditor finding #1: a checker that RAN and rejected must yield FAIL,
    # even when no certificate verified. INCONCLUSIVE is reserved for
    # "no deterministic checker executed".
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    unverified = make_check(passed=True)
    import dataclasses
    unverified_cert = dataclasses.replace(unverified.certificate, certificate_verified=False)
    ran_but_unverified = dataclasses.replace(unverified, certificate=unverified_cert)
    rejected = CheckResult(
        check_id="secrets_scan", passed=False, score=0.0, evidence=[],
        explanation="invariant failed", blocking=True, certificate=None,
    )
    report = make_report([ran_but_unverified, rejected])
    decision = PolicyEvaluator().evaluate(report, policy)
    assert decision.status == "FAIL"
    assert decision.rationale == "blocking_check_failed"


def test_policy_no_checks_executed_is_inconclusive():
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    report = make_report([])
    decision = PolicyEvaluator().evaluate(report, policy)
    assert decision.status == "INCONCLUSIVE"
    assert decision.rationale == "no_deterministic_checker_executed"


def test_policy_inability_plus_nonblocking_is_inconclusive():
    # Ghost-file shape: ungrounded semi check (blocking, unverified cert)
    # plus a failing non-blocking invariant. Nothing rejected → INCONCLUSIVE.
    import dataclasses
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    ran = make_check(passed=False)
    ungrounded = dataclasses.replace(
        ran, certificate=dataclasses.replace(ran.certificate, certificate_verified=False))
    soft_fail = CheckResult(
        check_id="provenance", passed=False, score=0.0, evidence=[],
        explanation="invariant failed", blocking=False, certificate=None,
    )
    report = make_report([ungrounded, soft_fail])
    decision = PolicyEvaluator().evaluate(report, policy)
    assert decision.status == "INCONCLUSIVE"
    assert decision.rationale == "checks_ran_but_nothing_established"


def test_invariant_blocking_flag_reaches_policy():
    # Non-blocking invariant failures must not FAIL the report on their own.
    from verifyci.verification.intent_align import evaluate_invariants
    from verifyci.contracts.verification_ir import Invariant
    inv = Invariant(invariant_id="p", rule="prov", compiled_query="provenance_check",
                    blocking=False)
    (check,), _ = evaluate_invariants("x", [inv], graph=None, evidence=[])
    assert check.passed is False
    assert check.blocking is False


def test_unestablished_blocking_pass_deflects_to_inconclusive():
    # Decided explicitly: pass-on-zero-edges is a different verdict from
    # pass-on-500-edges. A blocking check that established nothing routes
    # to INCONCLUSIVE even when nothing failed.
    import dataclasses
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    established_pass = make_check(passed=True)
    vacuous_pass = dataclasses.replace(
        make_check(passed=True), check_id="vacuous", established=False)
    report = make_report([established_pass, vacuous_pass])
    decision = PolicyEvaluator().evaluate(report, policy)
    assert decision.status == "INCONCLUSIVE"
    assert decision.rationale == "unestablished_or_unverified_checks"


def test_unestablished_nonblocking_pass_deflects_to_inconclusive():
    # P0 soundness: every passed check must be established, blocking or
    # not. An unestablished non-blocking pass can no longer launder into
    # PASS.
    import dataclasses
    policy = VerificationPolicy(
        policy_id="pol1",
        on_failure="block",
        on_inconclusive="human_review",
        on_human_review="block",
        require_deterministic_checker=True,
    )
    vacuous_soft = dataclasses.replace(
        make_check(passed=True), check_id="soft", blocking=False, established=False)
    report = make_report([make_check(passed=True), vacuous_soft])
    decision = PolicyEvaluator().evaluate(report, policy)
    assert decision.status == "INCONCLUSIVE"
    assert decision.rationale == "unestablished_or_unverified_checks"


def test_semi_formal_reasoner():
    reasoner = SemiFormalReasoner(model_name="test-model")
    cert = reasoner.verify(diff="test diff", graph=None)
    assert cert.certificate_id is not None
    assert cert.generated_by == "test-model"
    assert cert.certificate_verified is False
    assert cert.conclusion.result == "inconclusive"


def test_semi_formal_reasoner_with_opaque_graph():
    # An opaque non-graph object must NOT yield a verified certificate.
    reasoner = SemiFormalReasoner(model_name="test-model")
    cert = reasoner.verify(diff="test diff", graph=object())
    assert cert.certificate_id is not None
    assert cert.generated_by == "test-model"
    assert cert.certificate_verified is False
    assert cert.conclusion.result == "inconclusive"
    assert cert.evidence == []
    assert cert.execution_traces == []


def test_evaluate_invariants():
    results, metrics = evaluate_invariants("test diff", [], None)
    assert metrics.check_coverage == 0.0
    assert metrics.detection_recall is None
    assert metrics.detection_precision is None


def test_verify_evidence_coverage():
    pack = EvidencePack(
        query="test",
        entities=[],
        relationships=[],
        source_chunks=[SourceChunk(
            chunk_id="c1", file_path="test.py",
            line_start=1, line_end=5,
            content="test", source_hash="abc",
        )],
        provenance=[],
        scores={},
        retrieval_methods=["dense"],
        retrieval_timestamp=0.0,
        graph_revision="rev1",
    )
    assert verify_evidence_coverage(pack) is True
