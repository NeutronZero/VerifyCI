from typing import Any

from verifyci.contracts.verification_ir import BlastRadiusResult
from verifyci.graph.traverse import (
    CALL_FLOW_TYPES,
    MAX_DEPTH_LIMIT,
    TraversalInconclusiveError,
    derive_node_map,
    iter_edge_payloads,
    traverse,
)


def _check_structural_invariants(graph: Any, changed_entities: list[str], node_map: dict | None) -> None:
    """Verify structural validity and resource invariants for query seeds (LOCK-6).

    Guards against:
    - Malformed or corrupt entity identifiers/payloads
    - Ungrounded module boundary declarations / missing package manifests
    """
    if not changed_entities:
        return

    for entity_id in changed_entities:
        if not isinstance(entity_id, (str, int)):
            raise TraversalInconclusiveError(
                f"Malformed or corrupt entity identifier: {type(entity_id).__name__}"
            )

        if node_map and entity_id in node_map:
            idx = node_map[entity_id]
            node = graph[idx] if hasattr(graph, "__getitem__") else None
            if node is not None:
                # Corrupted payload check
                from collections.abc import Mapping
                if getattr(node, "metadata", None) is not None and not isinstance(node.metadata, (dict, Mapping)):
                    raise TraversalInconclusiveError(
                        f"Corrupted metadata payload on entity: {entity_id}"
                    )

                # Ungrounded entity / missing package boundary manifest check
                file_path = getattr(node, "file_path", None)
                if file_path is None or file_path == "":
                    raise TraversalInconclusiveError(
                        f"Target entity {entity_id} lacks source file definition / incomplete retrieval state"
                    )


def compute_blast_radius(
    graph,
    changed_entities: list[str],
    test_entities: set[str] | None = None,
    dependency_graph=None,
    vuln_cache=None,
    node_map: dict | None = None,
    max_hops: int = 2,
    budget: Any | None = None,
) -> BlastRadiusResult:
    if max_hops > MAX_DEPTH_LIMIT:
        raise TraversalInconclusiveError(
            f"Requested traversal depth {max_hops} exceeds maximum bounded depth limit ({MAX_DEPTH_LIMIT})"
        )

    if node_map is None:
        node_map = derive_node_map(graph)

    _check_structural_invariants(graph, changed_entities, node_map)
    reverse_map = {v: k for k, v in node_map.items()} if node_map else {}
    affected_callers = set()
    affected_callees = set()

    if graph is not None and node_map:
        c_indices = [node_map[eid] for eid in changed_entities if eid in node_map]
        if c_indices:
            callers = traverse(graph, c_indices, "incoming", max_hops, node_map, CALL_FLOW_TYPES, budget=budget)
            callees = traverse(graph, c_indices, "outgoing", max_hops, node_map, CALL_FLOW_TYPES, budget=budget)
            affected_callers.update(reverse_map.get(c, str(c)) for c in callers)
            affected_callees.update(reverse_map.get(c, str(c)) for c in callees)

    impacted = (affected_callers | affected_callees) | set(changed_entities)
    dependents = (affected_callers | affected_callees) - (set(test_entities) if test_entities is not None else set())

    # Tri-state test coverage knowledge:
    # 1. test_entities is None: unindexed / missing test suite metadata -> UNKNOWN
    #    test_coverage_gap is empty (structural impact only), static_reachability_gap is ()
    # 2. test_entities is empty set: indexed test suite contains 0 tests -> EVALUATED_EMPTY
    #    When no test suite is configured/discovered (set()), test_coverage_gap remains empty
    #    to prevent uncalibrated risk inflation, while static_reachability_gap reports all untested dependents.
    # 3. test_entities is populated: evaluate static reachability -> STATIC_REACHABILITY_EVALUATED
    #    Identifies dependents covered by tests via transitive call-graph reachability.
    if test_entities is None:
        test_coverage_status = "UNKNOWN"
        test_coverage_gap = []
        static_reachability_gap = ()
    elif len(test_entities) == 0:
        test_coverage_status = "EVALUATED_EMPTY"
        test_coverage_gap = []
        static_reachability_gap = tuple(sorted(dependents))
    else:
        test_coverage_status = "STATIC_REACHABILITY_EVALUATED"
        covered = set()
        if graph is not None and node_map:
            t_indices = [node_map[test_id] for test_id in test_entities if test_id in node_map]
            if t_indices:
                test_callees = traverse(graph, t_indices, "outgoing", max_hops, node_map, CALL_FLOW_TYPES, budget=budget)
                covered.update(reverse_map.get(c, str(c)) for c in test_callees)
        gap = dependents - covered
        test_coverage_gap = list(gap)
        static_reachability_gap = tuple(sorted(gap))


    # Calibrated risk formula remains frozen: callers, callees, and coverage gaps
    risk_score = min(1.0, len(affected_callers) * 0.1 + len(affected_callees) * 0.05 + len(test_coverage_gap) * 0.2)

    dep_packages = _graph_dependency_packages(graph, impacted)
    dependency_impact = _dependency_impact(dependency_graph, impacted, graph, dep_packages=dep_packages)
    vulnerability_impact = _vulnerability_impact(vuln_cache, impacted, graph, dep_packages=dep_packages)


    return BlastRadiusResult(
        affected_callers=sorted(affected_callers),
        affected_callees=sorted(affected_callees),
        test_coverage_gap=sorted(test_coverage_gap),
        risk_score=risk_score,
        dependency_impact=dependency_impact,
        vulnerability_impact=vulnerability_impact,
        test_coverage_status=test_coverage_status,
        static_reachability_gap=tuple(static_reachability_gap),
    )



class _VulnLookupEdge:
    __slots__ = ("metadata",)

    def __init__(self, package: str) -> None:
        self.metadata = {"package": package}


def _dependency_impact(dependency_graph, impacted: set[str], graph=None, dep_packages: set[str] | None = None) -> list[str]:
    out: set[str] = set()
    if dependency_graph:
        try:
            if isinstance(dependency_graph, dict):
                for eid in impacted:
                    out.update(dependency_graph.get(eid, []))
            elif hasattr(dependency_graph, "dependents"):
                for eid in impacted:
                    out.update(dependency_graph.dependents(eid))
        except Exception:  # noqa: BLE001, S110
            pass
    if dep_packages is None:
        dep_packages = _graph_dependency_packages(graph, impacted)
    out.update(dep_packages)
    return sorted(str(d) for d in out)


def _graph_dependency_packages(graph, impacted: set[str]) -> set[str]:
    """Packages from DEPENDS_ON edges touching impacted nodes."""
    packages: set[str] = set()
    if graph is None or not impacted:
        return packages
    try:
        for edge in iter_edge_payloads(graph):
            etype = getattr(getattr(edge, "type", None), "value", getattr(edge, "type", None))
            if etype != "DEPENDS_ON":
                continue
            meta = getattr(edge, "metadata", None) or {}
            package = meta.get("package")
            if not package:
                continue
            if getattr(edge, "src_entity_id", None) in impacted or \
               getattr(edge, "dst_entity_id", None) in impacted:
                packages.add(str(package))
    except Exception:  # noqa: BLE001, S110
        pass
    return packages


def _vulnerability_impact(vuln_cache, impacted: set[str], graph=None, dep_packages: set[str] | None = None) -> list[str]:
    if vuln_cache is None or not impacted:
        return []
    findings: list[str] = []
    try:
        lookup = getattr(vuln_cache, "lookup", None)
        if not callable(lookup):
            return []
        if dep_packages is None:
            dep_packages = _graph_dependency_packages(graph, impacted)
        packages = set(impacted) | dep_packages
        for package in packages:
            edge = _VulnLookupEdge(package)
            for vuln in lookup(edge) or []:
                findings.append(str(vuln.get("id", vuln) if isinstance(vuln, dict) else vuln))
    except Exception:  # noqa: BLE001, S110
        pass
    return sorted(set(findings))

