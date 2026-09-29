from src.verification.blast_radius import blast_radius_check


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
    # diff on it, silently, forever. Now it is inability (INCONCLUSIVE
    # at policy), never a clean bill of health.
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


def test_blast_wrapper_blocks_high_risk():
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
