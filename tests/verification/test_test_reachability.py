import rustworkx as rx
import pytest

from verifyci.contracts.edge import Edge, EdgeType
from verifyci.contracts.entity import Entity, EntityType
from verifyci.retrieval.blast_radius import compute_blast_radius
from verifyci.verification.blast_radius import blast_radius_check


def _build_test_graph():
    """Graph topology:
    test_auth (test) -> calls -> auth_helper (prod) -> calls -> verify_token (prod)
    payment_handler (prod) -> calls -> charge_card (prod)  [untested]
    """
    g = rx.PyDiGraph()
    node_map = {}

    def _add(id_, name, file_path):
        ent = Entity(
            repository_id="repo",
            logical_entity_id=id_,
            revision_entity_id=id_,
            type=EntityType.FUNCTION,
            name=name,
            file_path=file_path,
            line_start=1,
            line_end=10,
            language="python",
            source_hash="h",
            revision_id="rev1",
        )
        idx = g.add_node(ent)
        node_map[id_] = idx
        return idx

    _add("test_auth", "test_auth", "tests/test_auth.py")
    _add("auth_helper", "auth_helper", "verifyci/auth.py")
    _add("verify_token", "verify_token", "verifyci/auth.py")
    _add("payment_handler", "payment_handler", "verifyci/pay.py")
    _add("charge_card", "charge_card", "verifyci/pay.py")

    def _link(src, dst):
        edge = Edge(
            id=f"{src}->{dst}",
            revision_id="rev1",
            src_entity_id=src,
            dst_entity_id=dst,
            type=EdgeType.CALLS,
            valid_from=0.0,
        )
        g.add_edge(node_map[src], node_map[dst], edge)

    _link("test_auth", "auth_helper")
    _link("auth_helper", "verify_token")
    _link("payment_handler", "charge_card")

    return g, node_map


def test_tri_state_test_reachability_unknown():
    g, node_map = _build_test_graph()

    # 1. test_entities is None -> UNKNOWN
    res_unknown = compute_blast_radius(
        graph=g,
        changed_entities=["verify_token"],
        test_entities=None,
        node_map=node_map,
    )
    assert res_unknown.test_coverage_status == "UNKNOWN"
    assert res_unknown.static_reachability_gap == ()
    assert res_unknown.test_coverage_gap == []
    # Calibrated risk: auth_helper and test_auth are callers (2 * 0.1 = 0.2)
    assert pytest.approx(res_unknown.risk_score, 0.01) == 0.2


def test_tri_state_test_reachability_evaluated_empty():
    g, node_map = _build_test_graph()

    # 2. test_entities is set() -> EVALUATED_EMPTY
    res_empty = compute_blast_radius(
        graph=g,
        changed_entities=["verify_token"],
        test_entities=set(),
        node_map=node_map,
    )
    assert res_empty.test_coverage_status == "EVALUATED_EMPTY"
    assert "auth_helper" in res_empty.static_reachability_gap
    # Risk score formula remains frozen (2 callers * 0.1 = 0.2)
    assert pytest.approx(res_empty.risk_score, 0.01) == 0.2


def test_static_reachability_evaluated_with_witnesses():
    g, node_map = _build_test_graph()

    # verify_token is called by auth_helper, which is called by test_auth
    # Therefore, auth_helper is reachable from test_auth!
    res_covered = compute_blast_radius(
        graph=g,
        changed_entities=["verify_token"],
        test_entities={"test_auth"},
        node_map=node_map,
    )
    assert res_covered.test_coverage_status == "STATIC_REACHABILITY_EVALUATED"
    # auth_helper is reachable from test_auth, so gap is empty!
    assert res_covered.static_reachability_gap == ()

    # Now test payment_handler which has NO test callers
    res_untested = compute_blast_radius(
        graph=g,
        changed_entities=["payment_handler"],
        test_entities={"test_auth"},
        node_map=node_map,
    )
    assert res_untested.test_coverage_status == "STATIC_REACHABILITY_EVALUATED"
    # charge_card is callee of payment_handler and not reachable from test_auth
    assert "charge_card" in res_untested.static_reachability_gap


def test_blast_radius_check_preserves_none_test_entities():
    g, node_map = _build_test_graph()
    blast, check = blast_radius_check(
        graph=g,
        changed_entities=["verify_token"],
        test_entities=None,
        node_map=node_map,
    )
    assert blast.test_coverage_status == "UNKNOWN"
    assert blast.static_reachability_gap == ()


def test_risk_score_calculation_unchanged_across_test_metadata_modes():
    g, node_map = _build_test_graph()

    # Identical changed entity: payment_handler (has 1 callee: charge_card, 0 callers)
    # Base structural risk: 0 callers * 0.1 + 1 callee * 0.05 = 0.05
    res_none = compute_blast_radius(g, ["payment_handler"], None, node_map=node_map)
    res_empty = compute_blast_radius(g, ["payment_handler"], set(), node_map=node_map)

    assert res_none.risk_score == pytest.approx(0.05)
    assert res_empty.risk_score == pytest.approx(0.05)
    assert res_none.risk_score == res_empty.risk_score

