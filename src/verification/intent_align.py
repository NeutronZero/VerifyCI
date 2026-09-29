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

#: Keyword with optional underscore/dash affixes: DB_PASSWORD,
#: AWS_SECRET_ACCESS_KEY, APP_AUTH_TOKEN. A bare \b boundary misses every
#: one of these — and real .env files are always prefixed. Cost, stated
#: plainly: `get_password = "..."` / `old_password = "..."` now match
#: too. For a fail-closed gate that is correct (it IS a hardcoded
#: password); the allowlist demote covers fixtures.
_KEY = (r"(?:[A-Za-z0-9_]*[_-])?(?:password|passwd|secret|api[_-]?key"
        r"|auth[_-]?token|private[_-]?key)(?:[_-][A-Za-z0-9_]+)?")

SECRET_RE = re.compile(
    r"(?i)" + _KEY + r"\s*[:=]\s*['\"][^'\"]{3,}['\"]"
)

#: Unquoted assignments. The value must be 12+ chars with no parens,
#: quotes, or comment markers, so `password = get_password()` and
#: `token = os.environ["X"]` do not match but
#: `DB_PASSWORD=s3cr3tPr0dValue` does. Short unquoted values stay
#: outside the scanner's reach by design (documented residual).
UNQUOTED_SECRET_RE = re.compile(
    r"(?i)" + _KEY + r"\s*[:=]\s*([^\s()\"'`#;]{12,})(?=\s*(?:#|$))"
)

#: High-signal credential shapes that need no keyword context.
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
CONN_STR_RE = re.compile(r"://[^/\s:()\"']+:[^/\s@()\"']{4,}@")

_SECRET_PATTERNS = (SECRET_RE, UNQUOTED_SECRET_RE, AWS_KEY_RE, PEM_RE, JWT_RE, CONN_STR_RE)


def _has_secret(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)

#: Path segments whose secret-shaped strings are fixtures, not findings.
#: A secrets hit confined to these demotes to inability (INCONCLUSIVE via
#: `established=False`) instead of FAIL — the fixture-blindness boundary,
#: decided explicitly rather than tuned away.
ALLOWLISTED_DIRS = frozenset({"tests", "test", "fixtures", "fixture",
                              "examples", "example", "e2e"})


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
        passed, coverage, established = _check_invariant(diff, invariant, graph, evidence or [])
        results.append(CheckResult(
            check_id=str(uuid.uuid4()),
            passed=passed,
            score=1.0 if passed else 0.0,
            evidence=[],
            explanation=f"invariant_{invariant.invariant_id}_{'passed' if passed else 'failed'}"
                        f" ({coverage})",
            blocking=invariant.blocking,
            established=established,
        ))

    coverage = 1.0 if results else 0.0
    if expected_violated is None:
        recall = precision = None
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
        passed, coverage, established = _check_invariant(diff, invariant, graph, evidence or [])
        results.append(CheckResult(
            check_id=str(uuid.uuid4()), passed=passed,
            score=1.0 if passed else 0.0, evidence=[],
            explanation=f"invariant_{invariant.invariant_id} ({coverage})",
            blocking=invariant.blocking,
            established=established,
        ))
        expected.append(bool(violated))
    recall, precision = _score_against_labels(results, expected)
    return InvariantMetrics(
        check_coverage=1.0 if results else 0.0,
        detection_recall=recall,
        detection_precision=precision,
    )


def _check_invariant(diff: str, invariant: Invariant, graph: Any, evidence: list
                     ) -> tuple[bool, str, bool]:
    """Return (passed, coverage_note, established).

    `established=False` means the check ran against nothing (e.g. zero
    relevant edges): inability, which policy routes to INCONCLUSIVE rather
    than counting as a rejection or a meaningful pass. Unknown or empty
    queries fail closed (passed=False, established=True — the failure is a
    real rejection of an unevaluable rule)."""
    query = (invariant.compiled_query or "").strip()
    if not query:
        return False, "empty query (fail-closed)", True
    if query == "secrets_scan":
        return _scan_secrets(diff)
    if query == "provenance_check":
        return bool(evidence), f"evidence items={len(evidence)}", True
    if query.startswith("forbid_call:"):
        name = query[len("forbid_call:"):].strip()
        violated, examined, evaluated = _graph_search(graph, name, "CALLS")
        if not evaluated:
            return False, f"graph traversal failed for forbid_call:{name} (fail-closed)", True
        return not violated, _coverage_note(examined, "CALLS", name), examined > 0
    if query.startswith("forbid_import:"):
        name = query[len("forbid_import:"):].strip()
        violated, examined, evaluated = _graph_search(graph, name, "IMPORTS")
        if not evaluated:
            return False, f"graph traversal failed for forbid_import:{name} (fail-closed)", True
        return not violated, _coverage_note(examined, "IMPORTS", name), examined > 0
    return False, f"unknown query kind (fail-closed): {query[:40]}", True


def _coverage_note(examined: int, edge_type: str, name: str) -> str:
    if examined <= 0:
        return f"no {edge_type} edges in graph — vacuous pass for {name!r}"
    return f"examined {examined} {edge_type} edges for {name!r}"


def _is_allowlisted(path: str) -> str | None:
    """Return the matching allowlist rule, or None. The rule name travels
    into the verdict so a reviewer sees *why* a hit was demoted."""
    parts = [p.lower() for p in path.replace("\\", "/").split("/")]
    for p in parts:
        if p in ALLOWLISTED_DIRS:
            return f"directory {p!r}"
    if path.endswith(".example"):
        return "suffix '.example'"
    return None


def _scan_secrets(diff: str) -> tuple[bool, str, bool]:
    """Scan every added line in the diff, attributed per file. A hit
    outside allowlisted paths is a rejection. A hit confined to
    allowlisted paths (fixtures, examples) is inability
    (`established=False` → INCONCLUSIVE), not a pass and not a FAIL.

    Added lines are collected with `iter_added_lines`, not by splitting
    on `@@`: lines smuggled outside hunk regions (preamble, header-only
    sections) previously bypassed the scanner entirely while still
    grounding the diff. Lines attributable to no file fail as unscoped.
    """
    from src.verification.diffmap import iter_added_lines
    if not diff:
        return True, "empty diff, nothing to scan", True
    hit_files: list[str] = []
    unscoped = False
    for file, content in iter_added_lines(diff):
        if not _has_secret(content):
            continue
        if file is None:
            unscoped = True
        else:
            hit_files.append(file)
    if unscoped:
        return False, "secret-shaped string (unscoped diff lines)", True
    if not hit_files:
        return True, "diff text scanned", True
    outside = [f for f in hit_files if _is_allowlisted(f) is None]
    if outside:
        return False, f"secret-shaped string in {outside[0]}", True
    rules = sorted({_is_allowlisted(f) or "?" for f in set(hit_files)})
    return True, (f"would have FAILED, demoted because {', '.join(rules)} matched "
                  f"{sorted(set(hit_files))}"), False


def _graph_search(graph: Any, name: str, edge_type: str) -> tuple[bool, int, bool]:
    """Return (violation_found, edges_examined, evaluated).

    A broken graph (traversal raises) is NOT "no violation found": it is
    unevaluable, and the caller fails closed. `evaluated=False` is
    distinct from "zero edges examined" (graph=None or no name), which
    stays inability → INCONCLUSIVE.
    """
    if graph is None or not name:
        return False, 0, True
    try:
        index = {}
        nodes_fn = getattr(graph, "nodes", None)
        if callable(nodes_fn):
            for payload in nodes_fn():
                eid = getattr(payload, "revision_entity_id", None)
                if eid:
                    index[eid] = getattr(payload, "name", "")
        examined = 0
        for edge in iter_edge_payloads(graph):
            etype = getattr(getattr(edge, "type", None), "value", getattr(edge, "type", None))
            if etype != edge_type:
                continue
            examined += 1
            dst = getattr(edge, "dst_entity_id", None)
            if dst is not None and index.get(dst) == name:
                return True, examined, True
        return False, examined, True
    except Exception:  # noqa: BLE001
        return True, 0, False
