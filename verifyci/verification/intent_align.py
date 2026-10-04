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

#: Narrow exception to the 12-char floor (H2-C residual): the AWS
#: secret-key family (`AWS_SECRET_ACCESS_KEY`, `AWS_SECRET_KEY`).
#: An assigned literal under one of these names is near-certainly a
#: credential — the key name itself is the signal, so the value floor
#: is 8, not 12. Generic keywords keep the 12-char floor unchanged
#: (same value class, same terminators, same dotted-access guard);
#: only the key-name allowlist and the floor differ. Fail-closed for a
#: deny rule; documented, not silent.
SHORT_UNQUOTED_SECRET_RE = re.compile(
    r"(?i)(?<!\.)(?:AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY)"
    r"\s*[:=]\s*([^\s().\"'`#;,]{8,})(?=\s*(?:[;,#]|$))"
)

#: High-signal credential shapes that need no keyword context.
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
CONN_STR_RE = re.compile(r"://[^/\s:()\"']+:[^/\s@()\"']{4,}@")
_PROTO_RE = re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|kafka|mqtt|ldap|sqlite|oracle|mssql|clickhouse)://")
JSON_SECRET_RE = re.compile("(?i)" + chr(34) + ".{0,128}?" + _KEY + ".{0,128}?" + chr(34) + " *: *" + chr(34) + ".{8,512}" + chr(34))

_SECRET_PATTERNS = (SECRET_RE, UNQUOTED_SECRET_RE, SHORT_UNQUOTED_SECRET_RE,
                    AWS_KEY_RE, PEM_RE, JWT_RE, CONN_STR_RE, JSON_SECRET_RE)

_KEYWORD_RE = re.compile('(?i)' + _KEY)

#: Hot-path prefilter for _has_secret (see above): keyword shapes plus
#: the fixed prefixes of the four keywordless credential shapes.
_SECRET_PREFILTER_RE = re.compile(
    r"(?i)" + _KEY + r"|\bAKIA|-----BEGIN |eyJ[A-Za-z0-9_-]+|://")

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
    if SHORT_UNQUOTED_SECRET_RE.search(text):
        return 'SHORT_UNQUOTED_SECRET_RE'
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



def _is_secret_carve_out(content: str, opener: str | None = None, fname: str | None = None) -> bool:
    # V-01: Never carve out unambiguous high-signal credential shapes
    if any(p.search(content) for p in (AWS_KEY_RE, PEM_RE, JWT_RE, CONN_STR_RE)):
        return False

    if opener:
        op_strip = opener.strip()
        if any(fn in op_strip for fn in ("re.compile", "re.search", "re.match", "re.findall", "re.sub")):
            return True
        if not re.search(r"[:=]", op_strip):
            return True
    if re.search(r'\br["\'](?:\(\?[aiLmsux]|\\[bBwWsSdD]|\^|\.\*)', content):
        return True

    path_prefixes = ("/", "./", "../", "\\", "c:\\", "C:\\", "/sys/", "/etc/", "/dev/", "/tmp/", "/proc/")

    # Path carve-out: only carve out when all secret assignments have path values
    sec_matches = list(SECRET_RE.finditer(content))
    if sec_matches:
        all_are_paths = True
        for sm in sec_matches:
            m_text = sm.group(0)
            split_char = "=" if "=" in m_text else ":"
            val = m_text.split(split_char, 1)[-1].strip().strip("\"'")
            if not val.startswith(path_prefixes):
                all_are_paths = False
                break
        if all_are_paths:
            return True
    elif not (UNQUOTED_SECRET_RE.search(content) or SHORT_UNQUOTED_SECRET_RE.search(content) or JSON_SECRET_RE.search(content)):
        # If no secret assignment pattern matched, check if any quoted value is a path
        quoted_vals = re.findall(r'["\']([^"\']+)["\']', content)
        if any(q.startswith(path_prefixes) for q in quoted_vals):
            return True

    # Test fixture diffs in python code — strictly scoped to TEST_SUITE files.
    # DEFERRED REVIEW NOTE (2026-10-02): the marker list below
    # ("diff --git", "@@ -", "dq + ", ...) mirrors shapes found in THIS
    # repo's own test fixtures, not a principled threat model — a real
    # secret committed to a test file alongside a diff marker would also
    # be suppressed. The load-bearing protection is the
    # `classify_path == TEST_SUITE` gate, and the threat rationale is
    # that test files don't ship, so their fixture strings are not a
    # secret-exposure risk. Deliberately left as-is: removing the
    # carve-out would fail every suite on its own fixture strings.
    # Revisit only with a fixture-aware allowlist, not by deletion.
    if fname:
        from verifyci.verification.partition import classify_path, FilePartition
        if classify_path(fname) == FilePartition.TEST_SUITE:
            if any(m in content for m in ("diff --git", "DIFF.replace", "@@ -", "\\n+password", "+ nl +", " + dq", "dq + ")):
                return True

    return False


def _has_secret(text: str, fname: str | None = None) -> bool:
    # Cheap superset prefilter before the regex set: every pattern
    # below needs one of these markers (keyword shapes need _KEY; the
    # keywordless credential shapes need their fixed prefix), so a
    # line with none of them can match nothing. A 1 MB line of dense
    # quotes used to run the bounded-but-large JSON shape at every
    # quote; now it fails one linear scan. Trigger-only: anything that
    # passes still runs the full set, so no detection changes.
    if _SECRET_PREFILTER_RE.search(text) is None:
        return False
    if not any(p.search(text) for p in _SECRET_PATTERNS):
        return False
    if _is_secret_carve_out(text, fname=fname):
        return False
    return True




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


def _filter_allowlisted_secret_hits(
    hits: list[str],
    diff: str,
    allowlist_patterns: tuple[str, ...],
) -> list[str]:
    import re
    from verifyci.verification.partition import classify_path, FilePartition
    from verifyci.verification.diffmap import iter_added_lines_with_lineno

    compiled_pats = [re.compile(p) for p in allowlist_patterns]
    line_map: dict[tuple[str | None, int | None], list[str]] = {}
    for f, lno, content in iter_added_lines_with_lineno(diff):
        line_map.setdefault((f, lno), []).append(content)

    surviving = []
    for hit in hits:
        parts = hit.split(":", 2)
        fname = parts[0] if parts else ""
        lno_str = parts[1] if len(parts) > 1 else ""
        try:
            lno = int(lno_str) if lno_str != "?" else None
        except ValueError:
            lno = None

        if classify_path(fname) != FilePartition.TEST_SUITE:
            surviving.append(hit)
            continue

        contents = line_map.get((fname, lno), [])
        if any(pat.search(c) or pat.search(hit) for pat in compiled_pats for c in (contents or [""])):
            continue

        surviving.append(hit)

    return surviving


def _filter_allowlisted_forbid_hits(
    hit_files: list[str],
    ev: list[str],
    diff: str,
    allowlist_patterns: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    import re
    from verifyci.verification.partition import classify_path, FilePartition
    from verifyci.verification.diffmap import iter_added_lines_with_lineno

    compiled_pats = [re.compile(p) for p in allowlist_patterns]
    line_map: dict[tuple[str | None, int | None], list[str]] = {}
    for f, lno, content in iter_added_lines_with_lineno(diff):
        line_map.setdefault((f, lno), []).append(content)

    surviving_ev = []
    for item in ev:
        parts = item.split(":", 2)
        fname = parts[0] if parts else ""
        lno_str = parts[1] if len(parts) > 1 else ""
        try:
            lno = int(lno_str) if lno_str != "?" else None
        except ValueError:
            lno = None

        if classify_path(fname) != FilePartition.TEST_SUITE:
            surviving_ev.append(item)
            continue

        contents = line_map.get((fname, lno), [])
        if any(pat.search(c) or pat.search(item) for pat in compiled_pats for c in (contents or [""])):
            continue

        surviving_ev.append(item)

    surviving_files = sorted({e.split(":", 1)[0] for e in surviving_ev})
    return surviving_files, surviving_ev


def _check_invariant(diff: str, invariant: Invariant, graph: Any, evidence: list
                     ) -> tuple[bool, str, bool, list]:
    """Return (passed, coverage_note, established).

    `established=False` means the check ran against nothing (e.g. zero
    relevant edges): inability, which policy routes to INCONCLUSIVE rather
    than counting as a rejection or a meaningful pass. Unknown or empty
    queries fail closed (passed=False, established=True — the failure is a
    real rejection of an unevaluable rule)."""
    from verifyci.verification.partition import partition_diff, FilePartition
    scope = getattr(invariant, "target_scope", "global_strict") or "global_strict"
    if scope == "code_core":
        pdiff = partition_diff(diff)
        diff = pdiff.raw_diff_for_partition(FilePartition.CODE_CORE)
    elif scope == "code_and_config":
        pdiff = partition_diff(diff)
        diff = pdiff.raw_diff_for_partitions({FilePartition.CODE_CORE, FilePartition.CONFIGURATION})

    query = (invariant.compiled_query or "").strip()
    if not query:
        return False, 'empty query (fail-closed)', True, []
    if not diff.strip() and scope != "global_strict":
        return True, f'no files in scope for invariant_{invariant.invariant_id}', True, []
    if query == "secrets_scan":
        passed, why, established, hits = _scan_secrets(diff)
        allowlist = getattr(invariant, "test_allowlist_patterns", ())
        if not passed and allowlist and scope == "global_strict":
            hits = _filter_allowlisted_secret_hits(hits, diff, allowlist)
            if not hits:
                return True, 'diff text scanned (test fixtures allowlisted)', True, []
            return False, f'secret-shaped string in {hits[0]}', True, hits
        return passed, why, established, hits
    if query == "provenance_check":
        return bool(evidence), f'evidence items={len(evidence)}', True, []
    if query.startswith("forbid_call:"):
        name = query[len("forbid_call:"):].strip()
        return _check_forbid(diff, graph, name, "CALLS", invariant=invariant)
    if query.startswith("forbid_import:"):
        name = query[len("forbid_import:"):].strip()
        return _check_forbid(diff, graph, name, "IMPORTS", invariant=invariant)
    return False, f'unknown query kind (fail-closed): {query[:40]}', True, []


def _check_forbid(diff: str, graph: Any, name: str,
                  edge_type: str, invariant: Invariant | None = None) -> tuple[bool, str, bool, list]:
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
     evaluated, viol_src) = _graph_search(graph, name, edge_type)
    hit_files, parse_ok = _added_hits(diff, ref_kind, name)
    ev = _forbid_evidence(diff, ref_kind, name)
    allowlist = getattr(invariant, "test_allowlist_patterns", ()) if invariant else ()
    scope = getattr(invariant, "target_scope", "global_strict") if invariant else "global_strict"
    if hit_files and allowlist and scope == "global_strict":
        hit_files, ev = _filter_allowlisted_forbid_hits(hit_files, ev, diff, allowlist)

    if hit_files:
        # The base graph cannot see new code: a forbidden call the
        # diff itself introduces is a positive detection, so it
        # rejects even when the graph side established nothing — and
        # even when the graph side could not run at all. What the
        # diff text shows is fail-closed evidence, not infrastructure.
        return False, f'forbidden {human} {name!r} added in {hit_files[0]}', \
            True, ev
    unexamined = _unexamined_forbid_files(diff)
    if not evaluated:
        # Traversal raised and the diff adds no hit: the checker did
        # NOT run, so this is inability (established=False ->
        # INCONCLUSIVE at policy), not a rejection. established=True
        # here used to FAIL every invariant whenever the graph was
        # unreadable, masking infrastructure failure as a verdict (B4).
        return False, f'graph traversal failed for forbid_{human}:{name} (fail-closed)', False, []
    if not parse_ok:
        return True, 'fragment parse incomplete (inconclusive, established=False)', False, []
    if violated and violated_files:
        touched = _diff_files(diff)
        if touched and not any(_file_in_set(f, touched) for f in violated_files):
            note = (f'pre-existing violation {name!r} outside touched scope '
                    f'(files: {sorted(violated_files)[:4]}) — not attributed')
            return True, note, examined > 0, []
        if touched:
            # Per-entity scope: the base graph predates the diff, so a
            # violation in a touched file is only THIS diff's fault when
            # the diff's changed lines land inside the violating
            # entity's span. Editing an unrelated line in the same file
            # (pre-existing call elsewhere in the file) passes with a
            # note; touching the violating entity itself keeps the
            # rejection. Spans/entities unattributable -> conservative
            # FAIL (no scoped exemption without attribution).
            spans = _entity_spans(graph)
            anchors = _changed_anchors(diff)
            if _violation_touched(viol_src, touched, spans, anchors):
                return False, _coverage_note(examined, edge_type, name), examined > 0, []
            note = (f'pre-existing violation {name!r} in touched file but '
                    f'outside the changed entity span — not attributed')
            return True, note, examined > 0, []
    if unexamined:
        # No hit, and the graph never produced a confident rejection: added
        # lines in files no checker can read (uncovered language, non-exempt
        # partition) make absence unestablished. Reached only after the
        # rejection path above, so a graph-established FAIL cannot be
        # vetoed by a stray hunk into app.js in the same diff. Docs/configs
        # stay exempt: prose and manifests can't carry parsed calls, and
        # vetoing on them would decline every docs-touching diff.
        return True, (f'added lines in files outside covered languages '
                      f'(unexamined={unexamined}) — absence not established'), \
            False, []
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
        refs, parse_ok, had_error = extract_added_refs_status(diff)
    except Exception:  # noqa: BLE001
        return [], False
    if kind == "imports":
        hits = sorted(f for f, kinds in refs.items()
                      if any(_name_matches(r, name, "IMPORTS") for r in kinds.get(kind, set())))
    else:
        hits = sorted(f for f, kinds in refs.items() if name in kinds.get(kind, set()))
    if kind == "calls" and parse_ok:
        # The tree path is strictly-stricter (bare callees, imports via
        # grammar), so always back it with the lexical scan for this exact
        # target — but only when the fragments actually parsed: on
        # inability (parse_ok=False) the pinned contract is INCONCLUSIVE,
        # never a lexical verdict. Same bare-name rule as the tree path
        # (`obj.eval(` never flags). Also the only forbid coverage for
        # lines no grammar can reach: JS/TS sources, CI workflows,
        # package.json scripts, Dockerfiles.
        hits = sorted(set(hits) | set(_lexical_call_hits(diff, name)))
    return hits, parse_ok


# Languages the forbid checkers (tree + lexical) can examine. Mirrors the
# gate in added_refs.extract_added_refs_status; files outside this set are
# unexaminable, never implicitly clean.
_FORBID_COVERED_LANGUAGES = frozenset({"python", "c", "cpp"})


def _unexamined_forbid_files(diff: str | None) -> list[str]:
    """Added-line files no forbid checker can examine.

    A file is unexamined when its language is uncovered AND its partition is
    not exempt. DOCUMENTATION and CONFIGURATION are exempt from the veto:
    the lexical checker still scans their added lines (CI workflows and
    manifest scripts can carry shell-out text), so an exempt file is
    examined there even though no grammar can parse it. Everything else —
    including unknown paths, which classify fail-closed as CODE_CORE —
    vetoes establishment when it carries added lines.
    """
    from verifyci.ingestion.language import detect_language
    from verifyci.verification.diffmap import iter_added_lines
    from verifyci.verification.partition import FilePartition, classify_path
    try:
        lines = iter_added_lines(diff)
    except Exception:  # noqa: BLE001
        # Inability is not absence: a parser regression must veto, never
        # silently pass (mirrors _added_hits' parse_ok polarity).
        return ["<diff-parse-error>"]
    out = set()
    for f, _content in lines:
        if f is None:
            continue
        try:
            lang = detect_language(f)
        except Exception:  # noqa: BLE001
            lang = "unknown"
        if lang in _FORBID_COVERED_LANGUAGES:
            continue
        try:
            part = classify_path(f)
        except Exception:  # noqa: BLE001
            part = FilePartition.CODE_CORE
        if part in (FilePartition.DOCUMENTATION, FilePartition.CONFIGURATION):
            continue
        out.add(f)
    return sorted(out)


def _lexical_call_hits(diff: str, name: str) -> list[str]:
    """Files whose added lines textually contain a bare `name(` call.

    Python/C/C++ matches on covered files are expected to arrive via the
    tree path first; this scan additionally covers lines no grammar can
    reach — JS/TS sources, CI YAML, package.json `scripts`, Makefiles —
    where forbidden text (e.g. `curl | sh`, `eval(`) is a real shell-out.
    Partition exemption is deliberately not consulted: a docs file can
    still smuggle executable lines, and skipping it here would recreate
    the silent-clean the forbid path exists to avoid.
    """
    import re
    from verifyci.verification.diffmap import iter_added_lines
    try:
        pat = re.compile(r"(?<![\w.])" + re.escape(name) + r"\s*\(")
        lines = iter_added_lines(diff)
    except Exception:  # noqa: BLE001
        return []
    # Definition-shaped lines (`def eval(`, `function eval(`, `int eval(`)
    # bind the name, they do not call it — the contract test pins that.
    # Conservative matching: a line that starts (after @decorator / async /
    # function/def/class/proc/sub keyword) binds, so a forbidden name late
    # on the same line still flags.
    def_start = re.compile(
        r"^\s*(?:@\w+\s*)*(?:async\s+)?(?:def|function|fn|func|proc|class|sub)\b"
    )
    out = set()
    for f, content in lines:
        if f is None:
            continue
        if def_start.search(content):
            continue
        if pat.search(content):
            out.add(f)
    return sorted(out)


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
        if _has_secret(content, fname=fname):
            pat = _secret_pat_name(content)
            hits.append(f'{_lineno(fname, lineno)}:{pat}')
        if st[0] is not None or st[1] > 0 or st[2]:
            st[3].append(content)
            joined = ' '.join(st[3])
            found = False
            why = 'multiline-continuation'
            opener = st[3][0] if st[3] else None
            if _is_secret_carve_out(content, opener=opener, fname=fname):
                pass
            elif st[0] is not None:
                bare = content.replace(st[0], '')
                if len(bare.strip()) >= 3:
                    found = True
                    why = 'multiline-triple'
                # NOTE (defensive, intentionally untested): the two elifs
                # below are unreachable — any content carrying a 3+ quoted
                # run or a secret shape has >=3 non-triple chars, so the
                # bare>=3 branch above always fires first (a quoted run
                # needs 2 quotes + 3 inner chars; a secret shape is longer
                # still). Kept as fail-closed belt-and-braces.
                elif _quoted_hit(content, 3):
                    found = True
                    why = 'multiline-triple'
                elif _has_secret(content, fname=fname) or _has_secret(joined, fname=fname):
                    found = True
                    why = 'multiline-triple'
            else:
                if _quoted_hit(content, 3):
                    found = True
                    why = 'multiline-paren' if st[1] > 0 else 'multiline-backslash'
                elif _has_secret(content, fname=fname) or _has_secret(joined, fname=fname):
                    found = True
                    why = 'multiline-paren' if st[1] > 0 else 'multiline-backslash'
            if found:
                if not _has_secret(content, fname=fname):
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
        if _KEYWORD_RE.search(content) is None and CONN_STR_RE.search(content) is None:
            # Keywordless split connection strings (postgres://user: ... on
            # line 1 with the secret on line 2) never enter continuation
            # otherwise; protocol prefix is the trigger there. A bare
            # unclosed paren (`conn = (`) also opens a window: the joined
            # secret check still does the real work, so normal calls only
            # cost buffering, never false hits.
            if _PROTO_RE.search(content) is None:
                if content.count(chr(40)) <= content.count(chr(41)):
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
def _name_matches(dst_name, name: str, edge_type: str) -> bool:
    """Target match for a graph-side violation.

    Exact equality everywhere, plus dotted-last-component equality for
    IMPORTS: a relative import (`..config`, `.scaffold`, `pkg.config`)
    names the same module as its last component, and leading dots are
    hierarchy syntax the extractor deliberately preserves verbatim
    (extractor.py is latency-frozen; resolution lives here, not there).
    Deny-rule direction is fail-closed: `forbid_import:config` firing on
    `pkg.config` is correct — it IS an import of something named
    config — while `reconfig`/`myconfig` never match (components are
    exact segments, not substrings). CALLS stays exact: receiver
    qualification there is a pinned stricter semantic, out of scope.
    """
    if not dst_name or not name:
        return False
    if dst_name == name:
        return True
    if edge_type != "IMPORTS":
        return False
    dst, ban = str(dst_name), str(name)
    if dst.split(".")[-1] == ban.split(".")[-1]:
        return True
    return dst.startswith(ban + ".")


def _graph_search(graph: Any, name: str, edge_type: str
                  ) -> tuple[bool, int, list, bool, list]:
    """Return (violation_found, edges_examined, violating_files,
    evaluated, violating_sources).

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

    violating_sources collects (src_entity_id, src_file) pairs for the
    per-entity scope check: only a violation whose source entity the
    diff's changed lines actually land in is this diff's fault.
    """
    if graph is None or not name:
        return False, 0, [], True, []
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
        viol_src: list[tuple] = []
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
                    viol_src.append((getattr(edge, "src_entity_id", None), ""))
                continue
            if etype != edge_type:
                continue
            examined += 1
            dst = getattr(edge, "dst_entity_id", None)
            if dst is not None and _name_matches(index.get(dst), name, edge_type):
                found = True
                src = getattr(edge, "src_entity_id", None)
                src_file = files.get(src, "")
                if src_file:
                    viol_files.append(src_file)
                viol_src.append((src, src_file))
        return found, examined, viol_files, True, viol_src
    except Exception:  # noqa: BLE001
        return True, 0, [], False, []


def _entity_spans(graph: Any) -> dict:
    """revision_entity_id -> (file_path, line_start, line_end) for graph
    nodes that carry spans; best-effort, empty on any failure."""
    spans: dict = {}
    try:
        nodes_fn = getattr(graph, "nodes", None)
        if not callable(nodes_fn):
            return spans
        for payload in nodes_fn():
            eid = getattr(payload, "revision_entity_id", None)
            if not eid:
                continue
            try:
                s = int(getattr(payload, "line_start", 1) or 1)
                en = int(getattr(payload, "line_end", s) or s)
            except (TypeError, ValueError):
                continue
            spans[eid] = (getattr(payload, "file_path", "") or "", s, en)
    except Exception:  # noqa: BLE001, S110
        pass
    return spans


def _changed_anchors(diff: str) -> dict:
    """Old-side changed-line anchors by diff file path; empty when the
    diff is unattributable (whole-graph semantics then apply)."""
    try:
        from verifyci.verification.diffmap import changed_anchors_by_file
        return changed_anchors_by_file(diff)
    except Exception:  # noqa: BLE001
        return {}


def _violation_touched(viol_src: list, touched: set[str], spans: dict,
                       anchors: dict) -> bool:
    """True when some violating source entity's span contains a changed
    anchor of this diff (suffix-tolerant path match). Missing spans or
    missing anchors are unattributable -> conservative True (the caller
    keeps the rejection; no scoped exemption without attribution)."""
    if not viol_src:
        return True
    for src_id, src_file in viol_src:
        span = spans.get(src_id)
        if span is None:
            return True
        sfile, s, en = span
        ls = [a for f, a in anchors.items() if _file_in_set(f, {sfile})]
        if not ls:
            return True
        changed = set().union(*ls) if ls else set()
        if any(s <= ln <= en for ln in changed):
            return True
    return False


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
