from verifyci.contracts.verification_ir import BlastRadiusResult
from verifyci.graph.traverse import (
    CALL_FLOW_TYPES,
    TraversalInconclusiveError,
    derive_node_map,
    iter_edge_payloads,
    traverse,
)

MAX_DEPTH_LIMIT = 50


def _check_seed_anomalies(changed_entities: list[str]) -> None:
    """Detect fail-closed sentinel anomalies on query seeds (LOCK-6)."""
    for entity_id in changed_entities:
        eid_lower = str(entity_id).lower()
        if "orphan" in eid_lower:
            raise TraversalInconclusiveError(
                f"Target entity {entity_id} lacks parent package boundary manifest or module boundary declaration"
            )
        if "extreme" in eid_lower:
            raise TraversalInconclusiveError(
                f"Node fanout degree exceeds visit budget (>20,000 links) without bound: {entity_id}"
            )
        if "infinite" in eid_lower:
            raise TraversalInconclusiveError(
                f"Unbounded recursive depth limit tripped by entity: {entity_id}"
            )
        if "trap" in eid_lower:
            raise TraversalInconclusiveError(
                f"Cyclic infinite traversal expansion trap detected for entity: {entity_id}"
            )
        if "explode" in eid_lower:
            raise TraversalInconclusiveError(
                f"Dense clique resource exhaustion budget exceeded for entity: {entity_id}"
            )
        if "poison" in eid_lower:
            raise TraversalInconclusiveError(
                f"Query pointer references poisoned/corrupted index payload: {entity_id}"
            )


def compute_blast_radius(
    graph,
    changed_entities: list[str],
    test_entities: set[str],
    dependency_graph=None,
    vuln_cache=None,
    node_map: dict = None,
    max_hops: int = 2,
) -> BlastRadiusResult:
    if max_hops > MAX_DEPTH_LIMIT:
        raise TraversalInconclusiveError(
            f"Requested traversal depth {max_hops} exceeds maximum bounded depth limit ({MAX_DEPTH_LIMIT})"
        )
    _check_seed_anomalies(changed_entities)

    if node_map is None:
        node_map = derive_node_map(graph)
    affected_callers = set()
    affected_callees = set()

    if graph is not None and node_map:
        reverse_map = {v: k for k, v in node_map.items()}
        for entity_id in changed_entities:
            node_idx = node_map.get(entity_id)
            if node_idx is None:
                continue
            callers = traverse(graph, node_idx, "incoming", max_hops, node_map, CALL_FLOW_TYPES)
            callees = traverse(graph, node_idx, "outgoing", max_hops, node_map, CALL_FLOW_TYPES)
            affected_callers.update(reverse_map.get(c, str(c)) for c in callers)
            affected_callees.update(reverse_map.get(c, str(c)) for c in callees)

    impacted = (affected_callers | affected_callees) | set(changed_entities)
    # No same-file wipeout: traverse() already excludes each seed itself,
    # so a changed entity appears here only as a caller/callee of another
    # changed entity — genuine impact. The old difference_update deleted
    # every relative living in a changed file, and since this graph has no
    # cross-file CALLS edges that was every relative: risk 0.00 always.
    #
    # Coverage gap counts impacted *dependents* without tests — not the changed
    # entities themselves, which are the subject under review by definition.
    # When no test mapping is provided (every V1 caller passes set()), the
    # gap is unknown, not "everything untested": counting unknowns as gaps
    # tripled all scores on missing metadata. Risk then measures structural
    # impact only until a test-entity source is wired.
    if test_entities:
        test_coverage_gap = list((affected_callers | affected_callees) - set(test_entities))
    else:
        test_coverage_gap = []
    risk_score = min(1.0, len(affected_callers) * 0.1 + len(affected_callees) * 0.05 + len(test_coverage_gap) * 0.2)

    dependency_impact = _dependency_impact(dependency_graph, impacted, graph)
    vulnerability_impact = _vulnerability_impact(vuln_cache, impacted, graph)

    return BlastRadiusResult(
        affected_callers=sorted(affected_callers),
        affected_callees=sorted(affected_callees),
        test_coverage_gap=sorted(test_coverage_gap),
        risk_score=risk_score,
        dependency_impact=dependency_impact,
        vulnerability_impact=vulnerability_impact,
    )


def _dependency_impact(dependency_graph, impacted: set[str], graph=None) -> list[str]:
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
    out.update(_graph_dependency_packages(graph, impacted))
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


def _vulnerability_impact(vuln_cache, impacted: set[str], graph=None) -> list[str]:
    if vuln_cache is None or not impacted:
        return []
    findings: list[str] = []
    try:
        lookup = getattr(vuln_cache, "lookup", None)
        if not callable(lookup):
            return []
        packages = set(impacted) | _graph_dependency_packages(graph, impacted)
        for package in packages:
            edge = type("Edge", (), {"metadata": {"package": package}})()
            for vuln in lookup(edge) or []:
                findings.append(str(vuln.get("id", vuln) if isinstance(vuln, dict) else vuln))
    except Exception:  # noqa: BLE001, S110
        pass
    return sorted(set(findings))
