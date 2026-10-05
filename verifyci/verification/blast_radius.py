"""Verification-layer blast-radius check.

Thin wrapper over the graph-traversal implementation in
``verifyci.retrieval.blast_radius`` that additionally produces a ``CheckResult``
suitable for inclusion in a ``VerificationReport``.

The check is deliberately non-blocking: blast radius measures exposure
(reach), not a defect or violation. A risk at or above the threshold
routes to HUMAN_REVIEW through the policy fall-through — a human must
look — instead of FAIL, which is reserved for proven invariant breaches
(secrets, forbidden calls/imports, fabricated removals). Blocking on
exposure conflated reach with defect and hard-failed routine maintenance
on foundational modules.
"""
from typing import Any

from verifyci.contracts.verification_ir import BlastRadiusResult, CheckResult
from verifyci.graph.traverse import NodeMapError
from verifyci.retrieval.blast_radius import compute_blast_radius

__all__ = ["blast_radius_check"]

RISK_REVIEW_THRESHOLD = 0.8
# Deprecated alias: nothing blocks on exposure; the threshold routes to review.
RISK_BLOCK_THRESHOLD = RISK_REVIEW_THRESHOLD


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
    except (NodeMapError, RuntimeError) as e:
        # An unreadable graph is inability (never PASS; policy routes the
        # failed non-blocking check to HUMAN_REVIEW), never
        # a clean bill of health: the old code derived an empty map and
        # passed every diff on it, silently, forever.
        from verifyci.contracts.verification_ir import BlastRadiusResult as _BRR
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
        passed=blast.risk_score < RISK_REVIEW_THRESHOLD,
        score=1.0 - blast.risk_score,
        evidence=list(blast.affected_callers) + list(blast.affected_callees),
        explanation=f"risk_score={blast.risk_score:.2f}",
        blocking=False,
    )
    return blast, check
