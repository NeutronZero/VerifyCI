from src.verification.policy import PolicyEvaluator
from src.verification.semi_formal_reason import SemiFormalReasoner
from src.verification.intent_align import evaluate_invariants
from src.verification.evidence_verifier import verify_evidence_coverage
from src.contracts.verification_ir import (
    VerificationReport, CheckResult, VerificationPolicy, BlastRadiusResult,
)
from src.contracts.evidence import EvidencePack, SourceChunk, ProvenanceEntry


def make_check(passed=True, blocking=True):
    from src.contracts.verification_ir import Certificate, Premise, FileEvidence, ExecutionTrace, Conclusion
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
    assert metrics.detection_recall == 0.0
    assert metrics.detection_precision == 0.0


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
