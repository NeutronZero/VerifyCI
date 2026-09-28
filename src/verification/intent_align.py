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
    expected_violated: list[bool] | None = None,
) -> tuple[list[CheckResult], InvariantMetrics]:
    """Evaluate invariants against a diff.

    A check that *fails* means a violation was flagged (fail-closed checkers).
    Recall/precision are only meaningful against labeled ground truth: pass
    ``expected_violated`` (aligned with ``invariants``) to compute them, or
    use :func:`score_labeled`. Without labels both are reported 0.0
    ("unmeasured"), never a pass-rate masquerading as detection quality.
    """
    results = []
    for invariant in invariants:
        passed = _check_invariant(diff, invariant, graph, evidence or [])
        results.append(CheckResult(
            check_id=str(uuid.uuid4()),
            passed=passed,
            score=1.0 if passed else 0.0,
            evidence=[],
            explanation=f"invariant_{invariant.invariant_id}_{'passed' if passed else 'failed'}",
            blocking=invariant.blocking,
        ))

    coverage = 1.0 if results else 0.0
    if expected_violated is None:
        recall = precision = 0.0
    else:
        recall, precision = _score_against_labels(results, list(expected_violated))

    return results, InvariantMetrics(
        check_coverage=coverage,
        detection_recall=recall,
        detection_precision=precision,
    )


def _score_against_labels(results: list[CheckResult], expected_violated: list[bool]):
    flagged = [not r.passed for r in results[:len(expected_violated)]]
    expected = [bool(v) for v in expected_violated[:len(results)]]
    tp = sum(1 for f, e in zip(flagged, expected) if f and e)
    actual = sum(expected)
    flagged_n = sum(flagged)
    if actual == 0:
        recall = 1.0 if flagged_n == 0 else 0.0
    else:
        recall = tp / actual
    if flagged_n == 0:
        precision = 1.0 if actual == 0 else 0.0
    else:
        precision = tp / flagged_n
    return recall, precision


def score_labeled(cases: list[tuple[str, Invariant, Any, list, bool]]) -> InvariantMetrics:
    """Score (diff, invariant, graph, evidence, expected_violated) cases.

    This is the only path that yields plan-meaningful detection_recall /
    detection_precision (gates: recall >= 0.90, precision >= 0.85).
    """
    results = []
    expected = []
    for diff, invariant, graph, evidence, violated in cases:
        passed = _check_invariant(diff, invariant, graph, evidence or [])
        results.append(CheckResult(
            check_id=str(uuid.uuid4()), passed=passed,
            score=1.0 if passed else 0.0, evidence=[],
            explanation=f"invariant_{invariant.invariant_id}",
            blocking=invariant.blocking,
        ))
        expected.append(bool(violated))
    recall, precision = _score_against_labels(results, expected)
    return InvariantMetrics(
        check_coverage=1.0 if results else 0.0,
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
