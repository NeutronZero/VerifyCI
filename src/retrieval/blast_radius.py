from src.contracts.verification_ir import BlastRadiusResult
from src.graph.traverse import (
    CALL_FLOW_TYPES, derive_node_map, iter_edge_payloads, payload_id, traverse,
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
    if node_map is None:
        node_map = derive_node_map(graph)
    affected_callers = set()
    affected_callees = set()
    seed_indices: set[int] = set()

    if graph is not None and node_map:
        reverse_map = {v: k for k, v in node_map.items()}
        for entity_id in changed_entities:
            node_idx = node_map.get(entity_id)
            if node_idx is None:
                continue
            seed_indices.add(node_idx)
            callers = traverse(graph, node_idx, "incoming", max_hops, node_map, CALL_FLOW_TYPES)
            callees = traverse(graph, node_idx, "outgoing", max_hops, node_map, CALL_FLOW_TYPES)
            affected_callers.update(reverse_map.get(c, str(c)) for c in callers)
            affected_callees.update(reverse_map.get(c, str(c)) for c in callees)

    seed_ids = {node_map.get(i, str(i)) for i in seed_indices} if node_map else set()
    affected_callers.difference_update(changed_entities)
    affected_callees.difference_update(changed_entities)
    affected_callers.difference_update(seed_ids)
    affected_callees.difference_update(seed_ids)

    impacted = (affected_callers | affected_callees) | set(changed_entities)
    # Coverage gap counts impacted *dependents* without tests — not the changed
    # entities themselves, which are the subject under review by definition.
    test_coverage_gap = list((affected_callers | affected_callees) - set(test_entities))
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
