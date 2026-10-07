"""Independent Exact Traversal Oracle for CAP-007.

PROTOCOL LOCK-1 ENFORCEMENT:
- Zero imports from verifyci (clean-room reference oracle)
- Pure Python 3 standard library
- Exact graph traversal baseline for semantic blast radius, multi-hop reachability,
  and deterministic top-K ranking.
"""
from __future__ import annotations

from collections import deque
import hashlib
import json
from typing import Any

# Traversable semantic call-flow edge types (per MODE_PROTOCOL.md)
CALL_FLOW_EDGE_TYPES = frozenset({"CALLS", "IMPORTS", "INHERITS", "DEPENDS_ON"})


class ExactGraph:
    """Clean-room in-memory graph representation."""

    def __init__(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
        self.nodes = {n["id"]: n for n in nodes}
        self.outgoing: dict[str, list[tuple[str, str, dict[str, Any]]]] = {n["id"]: [] for n in nodes}
        self.incoming: dict[str, list[tuple[str, str, dict[str, Any]]]] = {n["id"]: [] for n in nodes}
        self.edge_records: list[dict[str, Any]] = edges

        for e in edges:
            src = e["src"]
            dst = e["dst"]
            etype = e.get("type", "CALLS")
            meta = e.get("metadata", {})
            self.outgoing.setdefault(src, []).append((dst, etype, meta))
            self.incoming.setdefault(dst, []).append((src, etype, meta))
            self.outgoing.setdefault(dst, [])
            self.incoming.setdefault(src, [])


def exact_traverse_bfs(
    graph: ExactGraph,
    seed_ids: list[str],
    direction: str,
    max_hops: int,
    allowed_types: frozenset[str] = CALL_FLOW_EDGE_TYPES,
) -> tuple[set[str], dict[str, int]]:
    """Exact breadth-first search traversal returning reached entities and hop distances."""
    valid_seeds = [s for s in seed_ids if s in graph.nodes or s in graph.outgoing]
    if not valid_seeds or max_hops <= 0:
        return set(), {}

    visited: set[str] = set(valid_seeds)
    hop_distances: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque([(s, 0) for s in valid_seeds])

    while queue:
        curr, depth = queue.popleft()
        if depth >= max_hops:
            continue

        neighbors = graph.incoming.get(curr, []) if direction == "incoming" else graph.outgoing.get(curr, [])
        for neighbor_id, etype, _ in neighbors:
            if etype in allowed_types:
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    hop_distances[neighbor_id] = depth + 1
                    queue.append((neighbor_id, depth + 1))

    # Exclude the original seeds from the reached impact set
    impact_set = visited - set(valid_seeds)
    # Ensure hop_distances strictly covers impact_set
    filtered_distances = {k: v for k, v in hop_distances.items() if k in impact_set}
    return impact_set, filtered_distances


def exact_compute_blast_radius(
    graph: ExactGraph,
    changed_entities: list[str],
    test_entities: set[str],
    max_hops: int = 2,
) -> dict[str, Any]:
    """Exact blast radius computation matching canonical semantics."""
    affected_callers, caller_hops = exact_traverse_bfs(graph, changed_entities, "incoming", max_hops)
    affected_callees, callee_hops = exact_traverse_bfs(graph, changed_entities, "outgoing", max_hops)

    impacted = (affected_callers | affected_callees) | set(changed_entities)
    coverage_gap = sorted(list((affected_callers | affected_callees) - set(test_entities))) if test_entities else []

    risk_score = min(
        1.0,
        len(affected_callers) * 0.1 + len(affected_callees) * 0.05 + len(coverage_gap) * 0.2,
    )

    # Dependency packages touched by DEPENDS_ON edges
    dependency_packages: set[str] = set()
    for e in graph.edge_records:
        if e.get("type") == "DEPENDS_ON":
            src = e.get("src")
            dst = e.get("dst")
            if src in impacted or dst in impacted:
                pkg = e.get("metadata", {}).get("package")
                if pkg:
                    dependency_packages.add(str(pkg))

    # Union hop distances: take minimum hop if an entity is reached both ways
    all_hops: dict[str, int] = {}
    for eid in (affected_callers | affected_callees):
        c_hop = caller_hops.get(eid, 999)
        e_hop = callee_hops.get(eid, 999)
        all_hops[eid] = min(c_hop, e_hop)

    return {
        "affected_callers": sorted(list(affected_callers)),
        "affected_callees": sorted(list(affected_callees)),
        "total_impacted_count": len(affected_callers | affected_callees),
        "test_coverage_gap": coverage_gap,
        "risk_score": round(risk_score, 4),
        "dependency_packages": sorted(list(dependency_packages)),
        "hop_distances": all_hops,
    }


def compute_deterministic_ranking(
    hop_distances: dict[str, int],
    k_values: list[int] = (10, 25, 50),
) -> dict[str, list[str]]:
    """Deterministic ranking ordered by (hop_distance ascending, entity_id ascending)."""
    # Sort key: (hop_distance, entity_id)
    sorted_entities = sorted(hop_distances.keys(), key=lambda eid: (hop_distances[eid], eid))
    rankings: dict[str, list[str]] = {}
    for k in k_values:
        rankings[f"top_{k}"] = sorted_entities[:k]
    return rankings


def evaluate_oracle_case(case: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Process a single CAP-007 benchmark case and emit ground-truth label and manifest."""
    case_id = case["id"]
    scenario_type = case.get("scenario_type", "standard")
    tripwire_anomaly = case.get("tripwire_anomaly")

    # Tripwire cases (e.g. infinite traversal trap or resource exhaustion) must fail closed with INCONCLUSIVE
    if scenario_type == "tripwire" or tripwire_anomaly is not None:
        label = {
            "id": case_id,
            "slice": case["slice"],
            "expected_status": "INCONCLUSIVE",
            "ground_truth": "fail_closed",
            "ground_truth_rationale": f"Resource / topology tripwire detected ({tripwire_anomaly}): must fail-closed with INCONCLUSIVE",
            "exact_impact_set": None,
            "canonical_digest": None,
            "rankings": None,
        }
        manifest = {
            "id": case_id,
            "node_count": len(case.get("graph", {}).get("nodes", [])),
            "edge_count": len(case.get("graph", {}).get("edges", [])),
            "query_count": len(case.get("queries", [])),
            "expected_status": "INCONCLUSIVE",
            "oracle_verified": True,
        }
        return label, manifest

    # Normal case: execute exact graph evaluation
    graph_data = case["graph"]
    graph = ExactGraph(graph_data["nodes"], graph_data["edges"])
    primary_query = case["queries"][0]
    seeds = primary_query["seeds"]
    max_hops = primary_query.get("max_hops", 2)
    test_entities = set(primary_query.get("test_entities", []))

    blast_res = exact_compute_blast_radius(graph, seeds, test_entities, max_hops=max_hops)
    rankings = compute_deterministic_ranking(blast_res["hop_distances"], k_values=[10, 25, 50])

    # Compute canonical digest of exact impact result
    canonical_payload = {
        "callers": blast_res["affected_callers"],
        "callees": blast_res["affected_callees"],
        "dependencies": blast_res["dependency_packages"],
        "rankings": rankings,
        "risk": blast_res["risk_score"],
    }
    canonical_digest = hashlib.sha256(
        json.dumps(canonical_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    label = {
        "id": case_id,
        "slice": case["slice"],
        "expected_status": "PASS",
        "ground_truth": "exact_traversal_verified",
        "ground_truth_rationale": f"Deterministic exact BFS traversal verified on {len(graph.nodes)} nodes",
        "exact_impact_set": sorted(list(set(blast_res["affected_callers"]) | set(blast_res["affected_callees"]))),
        "impact_counts": {
            "callers": len(blast_res["affected_callers"]),
            "callees": len(blast_res["affected_callees"]),
            "total": blast_res["total_impacted_count"],
        },
        "canonical_digest": canonical_digest,
        "rankings": rankings,
        "risk_score": blast_res["risk_score"],
    }

    manifest = {
        "id": case_id,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edge_records),
        "query_count": len(case["queries"]),
        "expected_status": "PASS",
        "canonical_digest": canonical_digest,
        "total_impacted": blast_res["total_impacted_count"],
        "oracle_verified": True,
    }
    return label, manifest
