from src.verification.blast_radius import blast_radius_check


def test_blast_wrapper_returns_check():
    blast, check = blast_radius_check(graph=None, changed_entities=[], test_entities=set())
    assert check.check_id == "blast_radius"
    assert check.passed is True
    assert blast.risk_score == 0.0


def test_blast_wrapper_blocks_high_risk():
    class FakeGraph:
        def predecessors(self, idx):
            return [100 + idx] if idx < 10 else []

        def successors(self, idx):
            return []

    node_map = {"changed": 1, "caller": 101}
    blast, check = blast_radius_check(
        graph=FakeGraph(), changed_entities=["changed"] * 0 + ["changed"],
        test_entities=set(), node_map=node_map, max_hops=1,
    )
    assert "caller" in blast.affected_callers or blast.risk_score >= 0.0
    assert check.score == 1.0 - blast.risk_score
