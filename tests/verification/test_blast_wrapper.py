from verifyci.verification.blast_radius import blast_radius_check


def test_blast_wrapper_returns_check():
    blast, check = blast_radius_check(graph=None, changed_entities=[], test_entities=set())
    assert check.check_id == "blast_radius"
    assert check.passed is True
    assert blast.risk_score == 0.0


def test_blast_wrapper_reports_same_file_callers():
    # The old difference_update wiped every relative living in a changed
    # file; the `or risk_score >= 0.0` (unconditionally true) hid it.
    class FakeGraph:
        def predecessors(self, idx):
            return [100 + idx] if idx < 10 else []

        def successors(self, idx):
            return []

    node_map = {"changed": 1, "caller": 101}
    blast, check = blast_radius_check(
        graph=FakeGraph(), changed_entities=["changed"],
        test_entities=set(), node_map=node_map, max_hops=1,
    )
    assert blast.affected_callers == ["caller"]
    assert blast.risk_score == 0.1
    assert check.passed is True
    assert check.score == 1.0 - blast.risk_score


def test_blast_wrapper_unreadable_graph_is_inability():
    # An unreadable graph used to derive an empty map and pass every
    # diff on it, silently, forever. Now it is inability (never PASS;
    # policy routes the failed non-blocking check to HUMAN_REVIEW).
    class _Broken:
        def node_indices(self):
            return [0]

        def nodes(self):
            raise RuntimeError("corrupt")

    blast, check = blast_radius_check(
        graph=_Broken(), changed_entities=["e1"], test_entities=set())
    assert check.passed is False
    assert check.established is False
    assert "graph_unreadable" in check.explanation


def test_blast_wrapper_corrupt_edge_api_is_inability():
    # traverse documents fail-closed on RuntimeError from the edge-data
    # path; the wrapper must convert it to inability, not propagate.
    class _CorruptEdges:
        def predecessors(self, idx):
            return [101] if idx == 1 else []

        def successors(self, idx):
            return []

        def get_all_edge_data(self, src, dst):
            raise RuntimeError("edge store corrupt")

    node_map = {"changed": 1, "caller": 101}
    _, check = blast_radius_check(
        graph=_CorruptEdges(), changed_entities=["changed"],
        test_entities=set(), node_map=node_map, max_hops=1,
    )
    assert check.passed is False
    assert check.established is False
    assert "graph_unreadable" in check.explanation


def test_blast_wrapper_high_risk_is_advisory():
    # Blast measures exposure, not violation: a high score fails the
    # check but must not block — policy routes it to HUMAN_REVIEW.
    # (Previously this test asserted blocking behavior; exposure is
    # not a defect and must not reject.)
    class FakeGraph:
        def predecessors(self, idx):
            return [100 + i for i in range(8)] if idx == 1 else []

        def successors(self, idx):
            return []

    node_map = {"changed": 1, **{f"caller{i}": 100 + i for i in range(8)}}
    blast, check = blast_radius_check(
        graph=FakeGraph(), changed_entities=["changed"],
        test_entities=set(), node_map=node_map, max_hops=1,
    )
    assert len(blast.affected_callers) == 8
    assert blast.risk_score >= 0.8
    assert check.passed is False
    assert check.blocking is False


def _decide(checks):
    import time
    import uuid
    from verifyci.contracts.verification_ir import (
        BlastRadiusResult, VerificationPolicy, VerificationReport,
    )
    from verifyci.verification.policy import PolicyEvaluator
    report = VerificationReport(
        report_id=str(uuid.uuid4()), task_id="t", policy_id="default",
        checks=checks,
        blast_radius=BlastRadiusResult(
            affected_callers=[], affected_callees=[], test_coverage_gap=[],
            risk_score=0.0, dependency_impact=[], vulnerability_impact=[]),
        timestamp=time.time(),
    )
    policy = VerificationPolicy(
        policy_id="default", on_failure="block", on_inconclusive="human_review",
        on_human_review="block", require_deterministic_checker=True)
    return PolicyEvaluator().evaluate(report, policy)


def test_high_blast_alone_routes_human_review():
    from verifyci.contracts.verification_ir import CheckResult
    _, check = blast_radius_check(
        graph=None, changed_entities=[], test_entities=set())
    passing = CheckResult(
        check_id="semi_formal", passed=True, score=1.0, evidence=[],
        explanation="t", blocking=True, certificate=None)
    high = CheckResult(
        check_id="blast_radius", passed=False, score=0.1, evidence=[],
        explanation="risk_score=0.90", blocking=False)
    assert check.blocking is False  # constructor contract, not just fixture
    decision = _decide([passing, high])
    assert (decision.status, decision.rationale) == (
        "HUMAN_REVIEW", "non_blocking_failures")


def test_violation_plus_high_blast_still_fails():
    # The rejections filter runs before the non-blocking fall-through:
    # a real violation alongside high exposure is FAIL, not review.
    from verifyci.contracts.verification_ir import CheckResult
    violation = CheckResult(
        check_id="secrets_scan", passed=False, score=0.0, evidence=[],
        explanation="secret-shaped string", blocking=True, established=True)
    high = CheckResult(
        check_id="blast_radius", passed=False, score=0.1, evidence=[],
        explanation="risk_score=0.90", blocking=False)
    decision = _decide([violation, high])
    assert (decision.status, decision.rationale) == ("FAIL", "blocking_check_failed")
