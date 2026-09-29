"""Verification-layer blast-radius check.

Thin wrapper over the graph-traversal implementation in
``src.retrieval.blast_radius`` that additionally produces a ``CheckResult``
suitable for inclusion in a ``VerificationReport``.
"""
from typing import Any

from src.contracts.verification_ir import BlastRadiusResult, CheckResult
from src.graph.traverse import NodeMapError
from src.retrieval.blast_radius import compute_blast_radius

__all__ = ["compute_blast_radius", "blast_radius_check"]

RISK_BLOCK_THRESHOLD = 0.8


def blast_radius_check(
    graph: Any,
    changed_entities: list[str],
    test_entities: set[str] | None = None,
    dependency_graph: Any = None,
    vuln_cache: Any = None,
    node_map: dict | None = None,
    max_hops: int = 2,
) -> tuple[BlastRadiusResult, CheckResult]:
    try:
        blast = compute_blast_radius(
            graph=graph,
            changed_entities=changed_entities,
            test_entities=test_entities or set(),
            dependency_graph=dependency_graph,
            vuln_cache=vuln_cache,
            node_map=node_map,
            max_hops=max_hops,
        )
    except NodeMapError as e:
        # An unreadable graph is inability (INCONCLUSIVE at policy), never
        # a clean bill of health: the old code derived an empty map and
        # passed every diff on it, silently, forever.
        from src.contracts.verification_ir import BlastRadiusResult as _BRR
        blast = _BRR(affected_callers=[], affected_callees=[],
                     test_coverage_gap=[], risk_score=0.0,
                     dependency_impact=[], vulnerability_impact=[])
        return blast, CheckResult(
            check_id="blast_radius",
            passed=False,
            score=0.0,
            evidence=[],
            explanation=f"graph_unreadable:{e}",
            established=False,
        )
    check = CheckResult(
        check_id="blast_radius",
        passed=blast.risk_score < RISK_BLOCK_THRESHOLD,
        score=1.0 - blast.risk_score,
        evidence=list(blast.affected_callers) + list(blast.affected_callees),
        explanation=f"risk_score={blast.risk_score:.2f}",
    )
    return blast, check
