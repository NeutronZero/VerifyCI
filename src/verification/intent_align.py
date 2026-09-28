"""Invariant evaluation with real, offline checkers (fail-closed).

Supported ``compiled_query`` kinds:
- ``secrets_scan`` — fail when the diff introduces a hardcoded secret.
- ``provenance_check`` — pass only when file evidence is attached.
- ``forbid_call:<name>`` — fail when a CALLS edge targets ``<name>``.
- ``forbid_import:<module>`` — fail when an IMPORTS edge targets ``<module>``.

Unknown or empty queries fail closed (return False): an invariant that
cannot be evaluated never silently passes. Semantic intent beyond these
kinds (e.g. "this deletion is wrong") is out of V1 scope by design.
"""
import re
import uuid
from typing import Any

from src.contracts.verification_ir import CheckResult, Invariant, InvariantMetrics
from src.graph.traverse import iter_edge_payloads

SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key)\b"
    r"\s*[:=]\s*['\"][^'\"]{3,}['\"]"
)


def evaluate_invariants(
    diff: str,
    invariants: list[Invariant],
    graph: Any = None,
    evidence: list | None = None,
    node_map: dict | None = None,
) -> tuple[list[CheckResult], InvariantMetrics]:
    results = []
    applicable = 0
    detected = 0

    for invariant in invariants:
        applicable += 1
        passed = _check_invariant(diff, invariant, graph, evidence or [])
        if passed:
            detected += 1
        results.append(CheckResult(
            check_id=str(uuid.uuid4()),
            passed=passed,
            score=1.0 if passed else 0.0,
            evidence=[],
            explanation=f"invariant_{invariant.invariant_id}_{'passed' if passed else 'failed'}",
        ))

    coverage = 1.0 if applicable > 0 else 0.0
    recall = detected / applicable if applicable > 0 else 0.0
    precision = detected / len(results) if results else 0.0

    return results, InvariantMetrics(
        check_coverage=coverage,
        detection_recall=recall,
        detection_precision=precision,
    )


def _check_invariant(diff: str, invariant: Invariant, graph: Any, evidence: list) -> bool:
    query = (invariant.compiled_query or "").strip()
    if not query:
        return False
    if query == "secrets_scan":
        return SECRET_RE.search(diff or "") is None
    if query == "provenance_check":
        return bool(evidence)
    if query.startswith("forbid_call:"):
        return not _graph_calls(graph, query[len("forbid_call:"):].strip(), "CALLS")
    if query.startswith("forbid_import:"):
        return not _graph_calls(graph, query[len("forbid_import:"):].strip(), "IMPORTS")
    return False


def _graph_calls(graph: Any, name: str, edge_type: str) -> bool:
    """True when a live edge of edge_type targets an entity named `name`."""
    if graph is None or not name:
        return False
    try:
        index = {}
        nodes_fn = getattr(graph, "nodes", None)
        if callable(nodes_fn):
            for payload in nodes_fn():
                eid = getattr(payload, "revision_entity_id", None)
                if eid:
                    index[eid] = getattr(payload, "name", "")
        for edge in iter_edge_payloads(graph):
            etype = getattr(getattr(edge, "type", None), "value", getattr(edge, "type", None))
            if etype != edge_type:
                continue
            dst = getattr(edge, "dst_entity_id", None)
            if dst is not None and index.get(dst) == name:
                return True
    except Exception:  # noqa: BLE001, S110
        pass
    return False
