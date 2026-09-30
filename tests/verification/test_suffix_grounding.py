"""Suffix-only grounding declines (INCONCLUSIVE), never PASS.

Exact-path grounding keeps established=True; a diff file with no exact
stored path (or several colliding ones) grounds weakly, so the
semi-formal check reports established=False and policy deflects.
"""
from types import SimpleNamespace

from verifyci.contracts.verification_ir import (
    BlastRadiusResult, Certificate, Conclusion, ExecutionTrace, FileEvidence,
    Premise, VerificationPolicy, VerificationReport,
)
from verifyci.verification.policy import PolicyEvaluator
from verifyci.verification.verification_ir import build_semi_check


def _payload(eid, path):
    return SimpleNamespace(
        revision_entity_id=eid, logical_entity_id=f"logical:{eid}",
        name="func", file_path=path, line_start=10, line_end=20,
        source_hash="abc123",
    )


def _verified_cert():
    return Certificate(
        certificate_id="cert1",
        premises=[Premise(premise_id="p1", statement="file_changed:app.py", source="app.py")],
        evidence=[FileEvidence(file_path="app.py", line_start=10, line_end=20,
                               snippet="x", source_hash="abc123")],
        execution_traces=[ExecutionTrace(trace_id="t1", path=["a", "b"], conditions=[])],
        conclusion=Conclusion(result="pass", reasoning="ok"),
        confidence=0.9,
        generated_by="semi_formal_reasoner",
        checked_by=["graph_traversal"],
        verification_method="semi_formal_reasoning",
        certificate_verified=True,
        timestamp=0.0,
    )


def _decide(check):
    report = VerificationReport(
        report_id="rep1", task_id="task1", policy_id="pol1", checks=[check],
        blast_radius=BlastRadiusResult(
            affected_callers=[], affected_callees=[], test_coverage_gap=[],
            risk_score=0.0, dependency_impact=[], vulnerability_impact=[]),
        timestamp=0.0,
    )
    policy = VerificationPolicy(
        policy_id="pol1", on_failure="block", on_inconclusive="human_review",
        on_human_review="block", require_deterministic_checker=True)
    return PolicyEvaluator().evaluate(report, policy).status


def test_exact_grounding_stays_established():
    check = build_semi_check(_verified_cert(), ["src/app.py"], [_payload("e1", "src/app.py")])
    assert check.passed is True and check.established is True
    assert _decide(check) == "PASS"


def test_suffix_only_grounding_is_unestablished():
    check = build_semi_check(_verified_cert(), ["app.py"], [_payload("e1", "src/app.py")])
    assert check.passed is True and check.established is False
    assert _decide(check) == "INCONCLUSIVE"


def test_colliding_paths_are_unestablished():
    ents = [_payload("e1", "src/app.py"), _payload("e2", "lib/app.py")]
    check = build_semi_check(_verified_cert(), ["app.py"], ents)
    assert check.established is False
    assert _decide(check) == "INCONCLUSIVE"
