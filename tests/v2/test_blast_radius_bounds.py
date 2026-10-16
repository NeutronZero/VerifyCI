"""Behaviour probes for the code paths that CAP-013 mutation testing showed were
uncovered.

These are ordinary product tests: each one asserts behaviour the verification
engine already implements. They exist because mutation testing demonstrated
that flipping traversal direction (MUT-01) and disabling required parameter
binding verification (MUT-03) both went undetected by the existing suite.
"""
from __future__ import annotations

from verifyci_v2.ingestion.diff_impact import (
    build_graph,
    compute_blast_radius,
    deterministic_ranking,
    traverse_bfs,
)
from verifyci_v2.symbolic.contract_checker import verify_call_contract


def _chain_graph() -> dict:
    """a -> b -> c plus a one-way leaf d.

    Direction matters: the inbound closure of `b` is {a}, the outbound closure
    is {c}. A traversal that ignores direction cannot produce both.
    """
    nodes = [
        {"id": "a", "name": "a", "module": "m", "type": "FUNCTION"},
        {"id": "b", "name": "b", "module": "m", "type": "FUNCTION"},
        {"id": "c", "name": "c", "module": "m", "type": "FUNCTION"},
        {"id": "d", "name": "d", "module": "m", "type": "FUNCTION"},
    ]
    edges = [
        {"src": "a", "dst": "b", "type": "CALLS"},
        {"src": "b", "dst": "c", "type": "CALLS"},
        {"src": "d", "dst": "a", "type": "CALLS"},
    ]
    return {"nodes": nodes, "edges": edges}


def test_traverse_bfs_respects_direction() -> None:
    graph = build_graph(_chain_graph()["nodes"], _chain_graph()["edges"])

    # Inbound from b: a at 1 hop, then d at 2 hops. Outbound: only c.
    callers, caller_hops = traverse_bfs(graph, ["b"], "incoming", 2)
    assert callers == {"a", "d"}
    assert caller_hops["a"] == 1
    assert caller_hops["d"] == 2

    callees, _ = traverse_bfs(graph, ["b"], "outgoing", 2)
    assert callees == {"c"}, "outbound closure of b must be its callee c"


def test_compute_blast_radius_unions_callers_and_callees() -> None:
    spec = _chain_graph()
    graph = build_graph(spec["nodes"], spec["edges"])

    radius = compute_blast_radius(graph, ["b"], [], max_hops=2)
    assert set(radius.affected_callers) == {"a", "d"}
    assert set(radius.affected_callees) == {"c"}
    assert set(radius.impacted) == {"a", "b", "c", "d"}
    # A seed is never its own impact.
    assert "b" not in set(radius.affected_callers) | set(radius.affected_callees)


def test_traverse_bfs_respects_hop_bound() -> None:
    graph = build_graph(_chain_graph()["nodes"], _chain_graph()["edges"])

    one_hop, _ = traverse_bfs(graph, ["b"], "incoming", 1)
    assert one_hop == {"a"}, "hop bound of 1 must stop before d (2 hops away)"

    two_hop, hops = traverse_bfs(graph, ["b"], "incoming", 2)
    assert two_hop == {"a", "d"}
    assert hops["d"] == 2


def test_traverse_bfs_excludes_non_call_flow_edge_types() -> None:
    nodes = [
        {"id": "x", "name": "x", "module": "m", "type": "FUNCTION"},
        {"id": "y", "name": "y", "module": "m", "type": "FUNCTION"},
    ]
    # A non-semantic edge type must not extend reachability.
    edges = [{"src": "y", "dst": "x", "type": "ANNOTATION"}]
    graph = build_graph(nodes, edges)

    reached, _ = traverse_bfs(graph, ["x"], "incoming", 3)
    assert reached == set(), "ANNOTATION edges are not semantic reachability"


def test_deterministic_ranking_orders_by_hop_then_id() -> None:
    hops = {"z": 1, "a": 1, "m": 2, "b": 2}
    ranking = deterministic_ranking(hops, k_values=(10,))
    assert list(ranking["top_10"]) == ["a", "z", "b", "m"]
    # Same input must always yield the same order.
    assert deterministic_ranking(dict(reversed(list(hops.items()))), (10,)) == ranking


def test_required_param_binding_mismatch_fails_closed() -> None:
    """MUT-03 coverage: a wrong binding must not be reported as verified."""
    signature = {
        "name": "verify_token",
        "parameters": ["token", "strict", "algorithm"],
        "defaults": {},
    }
    ok = verify_call_contract(
        "verify_token(raw, strict=True, algorithm='RS256')",
        signature,
        {
            "callee": "verify_token",
            "required_param_bindings": {"strict": "True"},
            "forbidden_kwargs": {},
            "required_kwargs": {},
        },
    )
    assert ok.verdict == "VERIFIED"

    wrong = verify_call_contract(
        "verify_token(raw, strict=False, algorithm='RS256')",
        signature,
        {
            "callee": "verify_token",
            "required_param_bindings": {"strict": "True"},
            "forbidden_kwargs": {},
            "required_kwargs": {},
        },
    )
    assert wrong.verdict == "FAIL", "a mismatched parameter binding must FAIL"


def test_required_param_binding_missing_is_inconclusive() -> None:
    signature = {
        "name": "verify_token",
        "parameters": ["token", "strict"],
        "defaults": {},
    }
    result = verify_call_contract(
        "verify_token(raw)",
        signature,
        {
            "callee": "verify_token",
            "required_param_bindings": {"strict": "True"},
            "forbidden_kwargs": {},
            "required_kwargs": {},
        },
    )
    assert result.verdict == "INCONCLUSIVE"