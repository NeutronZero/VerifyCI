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

from verifyci.contracts.verification_ir import CheckResult, Invariant, InvariantMetrics
from verifyci.graph.traverse import iter_edge_payloads

#: Keyword with optional underscore/dash affixes: DB_PASSWORD,
#: AWS_SECRET_ACCESS_KEY, APP_AUTH_TOKEN. A bare \b boundary misses every
#: one of these — and real .env files are always prefixed. Cost, stated
#: plainly: `get_password = "..."` / `old_password = "..."` now match
#: too. For a fail-closed gate that is correct (it IS a hardcoded
#: password); fixtures fail like any secret, no allowlist.
#:
#: Two bounds keep the matcher linear-time and precise. The affix
#: repetitions are capped at 64 chars: unbounded `*` inside the optional
#: group backtracked quadratically, and a 1 MB minified line burned
#: minutes of CPU behind an unauthenticated endpoint. Real affixes
#: (`AWS_SECRET_ACCESS_`) are an order of magnitude shorter.
_KEY = (r"(?:[A-Za-z0-9_]{0,64}[_-])?(?:password|passwd|secret|api[_-]?key"
        r"|auth[_-]?token|private[_-]?key)(?:[_-][A-Za-z0-9_]{1,64})?")

SECRET_RE = re.compile(
    r"(?i)" + _KEY + r"\s*[:=]\s*['\"][^'\"]{3,}['\"]"
)

#: Unquoted assignments. The value must be 12+ chars with no parens,
#: quotes, dots, or comment markers, so `password = get_password()`,
#: `token = os.environ["X"]`, `self.password = user_provided_password`,
#: and `secret_key = config.SECRET_KEY_NAME` do not match — dotted
#: attribute access on either side is wiring, not a literal (real
#: dotted secrets are covered by the JWT and connection-string
#: patterns; the `(?<!\.)` guard covers the keyword side).
#: `DB_PASSWORD=s3cr3tPr0dValue` matches. The value may end
#: the line, a `#` comment, or a `;`/`,` terminator (C-style
#: `DB_PASSWORD=s3cr3tPr0dValue;`). Short unquoted values stay outside
#: the scanner's reach by design (documented residual).
UNQUOTED_SECRET_RE = re.compile(
    r"(?i)(?<!\.)" + _KEY + r"\s*[:=]\s*([^\s().\"'`#;,]{12,})(?=\s*(?:[;,#]|$))"
)

#: High-signal credential shapes that need no keyword context.
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
CONN_STR_RE = re.compile(r"://[^/\s:()\"']+:[^/\s@()\"']{4,}@")
JSON_SECRET_RE = re.compile("(?i)" + chr(34) + ".{0,128}?" + _KEY + ".{0,128}?" + chr(34) + " *: *" + chr(34) + ".{8,512}" + chr(34))

_SECRET_PATTERNS = (SECRET_RE, UNQUOTED_SECRET_RE, AWS_KEY_RE, PEM_RE, JWT_RE, CONN_STR_RE, JSON_SECRET_RE)

_KEYWORD_RE = re.compile('(?i)' + _KEY)

def _quoted_hit(text, min_len=3):
    # check quoted literals without regex, no doublequote chars in source
    dq = chr(34)
    sq = chr(39)
    start = 0
    while True:
        j = text.find(dq, start)
        if j < 0:
            break
        k = text.find(dq, j + 1)
        if k < 0:
            break
        if k - j - 1 >= min_len:
            return True
        start = k + 1
    start = 0
    while True:
        j = text.find(sq, start)
        if j < 0:
            break
        k = text.find(sq, j + 1)
        if k < 0:
            break
        if k - j - 1 >= min_len:
            return True
        start = k + 1
    return False

def _secret_pat_name(text):
    if SECRET_RE.search(text):
        return 'SECRET_RE'
    if UNQUOTED_SECRET_RE.search(text):
        return 'UNQUOTED_SECRET_RE'
    if AWS_KEY_RE.search(text):
        return 'AWS_KEY_RE'
    if PEM_RE.search(text):
        return 'PEM_RE'
    if JWT_RE.search(text):
        return 'JWT_RE'
    if CONN_STR_RE.search(text):
        return 'CONN_STR_RE'
    if JSON_SECRET_RE.search(text):
        return "JSON_SECRET_RE"
    return 'SECRET'

def _forbid_evidence(diff, kind, name):
    # file:line:pattern evidence, citing only lines the parser's own
    # matching would flag: bare `name(` calls (never `obj.name(`) and
    # word-boundary import mentions. Substring hits like `evaluation`
    # for `eval` must never appear here.
    import re
    from verifyci.verification.diffmap import iter_added_lines_with_lineno
    out = []
    if kind == "imports":
        pat = re.compile(r"(?<![\w])" + re.escape(name) + r"(?![\w])")
    else:
        pat = re.compile(r"(?<![\w.])" + re.escape(name) + r"\s*\(")
    for file, lineno, content in iter_added_lines_with_lineno(diff):
        if pat.search(content):
            fname = file if file is not None else 'unscoped'
            out.append(f'{fname}:{lineno if lineno is not None else "?"}:forbid_{kind}:{name}')
    return out



def _has_secret(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)




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
        passed, coverage, established, ev = _check_invariant(diff, invariant, graph, evidence or [])
        results.append(CheckResult(
            check_id=str(uuid.uuid4()),
            passed=passed,
            score=1.0 if passed else 0.0,
            evidence=list(ev),
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
        passed, coverage, established, ev = _check_invariant(diff, invariant, graph, evidence or [])
        results.append(CheckResult(
            check_id=str(uuid.uuid4()), passed=passed,
            score=1.0 if passed else 0.0, evidence=list(ev),
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
                     ) -> tuple[bool, str, bool, list]:
    """Return (passed, coverage_note, established).

    `established=False` means the check ran against nothing (e.g. zero
    relevant edges): inability, which policy routes to INCONCLUSIVE rather
    than counting as a rejection or a meaningful pass. Unknown or empty
    queries fail closed (passed=False, established=True — the failure is a
    real rejection of an unevaluable rule)."""
    query = (invariant.compiled_query or "").strip()
    if not query:
        return False, 'empty query (fail-closed)', True, []
    if query == "secrets_scan":
        return _scan_secrets(diff)
    if query == "provenance_check":
        return bool(evidence), f'evidence items={len(evidence)}', True, []
    if query.startswith("forbid_call:"):
        name = query[len("forbid_call:"):].strip()
        return _check_forbid(diff, graph, name, "CALLS")
    if query.startswith("forbid_import:"):
        name = query[len("forbid_import:"):].strip()
        return _check_forbid(diff, graph, name, "IMPORTS")
    return False, f'unknown query kind (fail-closed): {query[:40]}', True, []


def _check_forbid(diff: str, graph: Any, name: str,
                  edge_type: str) -> tuple[bool, str, bool, list]:
    """Shared forbid_call/forbid_import evaluation.

    ref_kind is the added_refs bucket key ("calls"/"imports"); human is
    the word used in the message ("call"/"import").

    Three sources of truth, in order:
    1. added lines referencing the target -> rejection (the base graph
       cannot see new code);
    2. the graph, scoped to files the diff touches: a violation that
       exists only in files the diff does not name is pre-existing, and
       pre-existing != introduced — it must not contaminate this diff's
       verdict (it is reported in the note);
    3. no diff attribution at all (unparseable/gibberish diff, empty
       file list) -> the whole-graph scan is all there is, and stays
       authoritative (this is the frozen B1 `forbid-direct` semantics:
       an unverifiable diff does not get a scoped pass).
    """
    ref_kind = "calls" if edge_type == "CALLS" else "imports"
    human = "call" if edge_type == "CALLS" else "import"
    (violated, examined, violated_files,
     evaluated) = _graph_search(graph, name, edge_type)
    if not evaluated:
        return False, f'graph traversal failed for forbid_{human}:{name} (fail-closed)', True, []
    hit_files, parse_ok = _added_hits(diff, ref_kind, name)
    if hit_files:
        # The base graph cannot see new code: a forbidden call the
        # diff itself introduces is a positive detection, so it
        # rejects even when the graph side established nothing.
        return False, f'forbidden {human} {name!r} added in {hit_files[0]}', \
            True, _forbid_evidence(diff, ref_kind, name)
    if not parse_ok:
        return True, 'fragment parse incomplete (inconclusive, established=False)', False, []
    if violated and violated_files:
        touched = _diff_files(diff)
        if touched and not any(_file_in_set(f, touched) for f in violated_files):
            note = (f'pre-existing violation {name!r} outside touched scope '
                    f'(files: {sorted(violated_files)[:4]}) — not attributed')
            return True, note, examined > 0, []
    return not violated, _coverage_note(examined, edge_type, name), examined > 0, []


def _added_hits(diff: str, kind: str, name: str) -> tuple[list[str], bool]:
    """Files whose added lines reference a forbidden target, plus whether
    every fragment parsed cleanly.

    Mirrors secrets_scan semantics: fail on detection, pass otherwise.
    A parse exception, or fragments that errored while yielding no refs
    at all, is inability (ok=False → INCONCLUSIVE), never a silent pass
    and never a violation. A syntactic claim about added lines — the
    graph-side check still runs either way.
    """
    if not diff or not name:
        return [], True
    from verifyci.verification.added_refs import extract_added_refs_status
    try:
        refs, parse_ok = extract_added_refs_status(diff)
    except Exception:  # noqa: BLE001
        return [], False
    return sorted(f for f, kinds in refs.items() if name in kinds.get(kind, set())), parse_ok


def _coverage_note(examined: int, edge_type: str, name: str) -> str:
    if examined <= 0:
        return f"no {edge_type} edges in graph — vacuous pass for {name!r}"
    return f"examined {examined} {edge_type} edges for {name!r}"




def _scan_secrets(diff: str) -> tuple[bool, str, bool, list]:
    # scan added lines with per file continuation, fail closed, evidence file line pattern
    from verifyci.verification.diffmap import iter_added_lines_with_lineno
    if not diff:
        return True, 'empty diff, nothing to scan', True, []
    tdq = chr(34) * 3
    tsq = chr(39) * 3
    states = {}
    hits = []

    def _lineno(fname, lineno):
        return f'{fname}:{lineno if lineno is not None else "?"}'

    for file, lineno, content in iter_added_lines_with_lineno(diff):
        fname = file if file is not None else 'unscoped'
        st = states.get(file)
        if st is None:
            st = [None, 0, False, [], 0]
            states[file] = st
        # single line hits, including high signal shapes in continuation lines
        if _has_secret(content):
            pat = _secret_pat_name(content)
            hits.append(f'{_lineno(fname, lineno)}:{pat}')
        if st[0] is not None or st[1] > 0 or st[2]:
            st[3].append(content)
            joined = ' '.join(st[3])
            found = False
            why = 'multiline-continuation'
            if st[0] is not None:
                bare = content.replace(st[0], '')
                if len(bare.strip()) >= 3:
                    found = True
                    why = 'multiline-triple'
                elif _quoted_hit(content, 3):
                    found = True
                    why = 'multiline-triple'
                elif _has_secret(content) or _has_secret(joined):
                    found = True
                    why = 'multiline-triple'
            else:
                if _quoted_hit(content, 3):
                    found = True
                    why = 'multiline-paren' if st[1] > 0 else 'multiline-backslash'
                elif _has_secret(content) or _has_secret(joined):
                    found = True
                    why = 'multiline-paren' if st[1] > 0 else 'multiline-backslash'
            if found:
                if not _has_secret(content):
                    hits.append(f'{_lineno(fname, lineno)}:{why}')
            if st[0] is not None:
                if st[0] in content:
                    st[0] = None
                    st[3] = []
            elif st[1] > 0:
                st[1] += content.count(chr(40)) - content.count(chr(41))
                if st[1] <= 0:
                    st[1] = 0
                    st[3] = []
            else:
                st[2] = False
                st[3] = []
            continue
        if _KEYWORD_RE.search(content) is None:
            continue
        if content.count(tdq) % 2 == 1:
            st[0] = tdq
            st[3] = [content]
            continue
        if content.count(tsq) % 2 == 1:
            st[0] = tsq
            st[3] = [content]
            continue
        if content.rstrip().endswith(chr(92)):
            st[2] = True
            st[3] = [content]
            continue
        stripped = content.rstrip()
        if stripped.endswith(chr(40)) and stripped.count(chr(40)) > stripped.count(chr(41)):
            st[1] = stripped.count(chr(40)) - stripped.count(chr(41))
            st[3] = [content]
            continue
    if not hits:
        return True, 'diff text scanned', True, []
    return False, f'secret-shaped string in {hits[0]}', True, hits
def _graph_search(graph: Any, name: str, edge_type: str
                  ) -> tuple[bool, int, list, bool]:
    """Return (violation_found, edges_examined, violating_files, evaluated).

    A broken graph (traversal raises) is NOT "no violation found": it is
    unevaluable, and the caller fails closed. `evaluated=False` is
    distinct from "zero edges examined" (graph=None or no name), which
    stays inability → INCONCLUSIVE.

    violating_files collects the file_path of each violating edge's
    source entity so the caller can distinguish a violation inside this
    diff's touched files from a pre-existing one elsewhere. An edge
    whose endpoints carry no file attribution yields an empty list,
    which conservatively keeps the whole-graph semantics (no scoped
    exemption is granted without attribution).
    """
    if graph is None or not name:
        return False, 0, [], True
    try:
        index = {}
        files = {}
        nodes_fn = getattr(graph, "nodes", None)
        if callable(nodes_fn):
            for payload in nodes_fn():
                eid = getattr(payload, "revision_entity_id", None)
                if eid:
                    index[eid] = getattr(payload, "name", "")
                    files[eid] = getattr(payload, "file_path", "") or ""
        examined = 0
        viol_files: list[str] = []
        found = False
        for edge in iter_edge_payloads(graph):
            etype = getattr(getattr(edge, "type", None), "value", getattr(edge, "type", None))
            if edge_type == "CALLS" and etype == "CALLS_UNRESOLVED":
                # Reachable only for graphs that link unresolved edges
                # (builder-linked graphs never do — see
                # test_calls_unresolved_is_unreachable_on_builder_graphs);
                # kept for fake/resolver-emitting graphs, and metadata
                # carries no file, so an unresolved hit is unattributed.
                examined += 1
                meta = getattr(edge, "metadata", None) or {}
                if isinstance(meta, dict) and meta.get("callee") == name:
                    found = True
                continue
            if etype != edge_type:
                continue
            examined += 1
            dst = getattr(edge, "dst_entity_id", None)
            if dst is not None and index.get(dst) == name:
                found = True
                src_file = files.get(getattr(edge, "src_entity_id", None), "")
                if src_file:
                    viol_files.append(src_file)
        return found, examined, viol_files, True
    except Exception:  # noqa: BLE001
        return True, 0, [], False


def _diff_files(diff: str) -> set[str]:
    """Files this diff names, normalized; empty when unattributable."""
    if not diff:
        return set()
    from verifyci.verification.diffmap import normalize_path, parse_diff_files
    try:
        return {normalize_path(f) for f in parse_diff_files(diff)}
    except Exception:  # noqa: BLE001
        return set()


def _file_in_set(entity_file: str, wanted: set[str]) -> bool:
    from verifyci.verification.diffmap import normalize_path
    f = normalize_path(entity_file)
    for w in wanted:
        if f == w or f.endswith("/" + w) or w.endswith("/" + f):
            return True
    return False
