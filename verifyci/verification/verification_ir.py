from bisect import bisect_left, bisect_right
import time
import uuid

from verifyci.contracts.verification_ir import (
    VerificationReport, CheckResult, BlastRadiusResult,
)


def build_semi_check(cert, files: list[str], entities: list,
                     diff: str | None = None) -> CheckResult:
    """Build the semi-formal CheckResult, appending a suffix-grounding
    ambiguity note when one diff path matched entities under several stored
    paths. Single shared constructor so the tripwire can't rot in one of
    the three call sites (executor, MCP, CLI).

    Suffix-only grounding is weaker than exact-path grounding: when a
    diff file grounds but no stored entity carries its exact normalized
    path (or several stored paths collide on it), the check reports
    established=False, so policy routes to INCONCLUSIVE — a
    suffix-grounded diff can decline, never PASS.

    A file whose content the diff does not carry (binary, or mode-only)
    is the same inability class: when it shares a diff with groundable
    text, the text half must not earn a PASS that hides the unreadable
    half. established=False here makes the mixed text+binary case route
    to INCONCLUSIVE rather than PASS. (diff=None callers — legacy unit
    tests — skip the check; the production call sites pass it.)
    """
    from verifyci.verification.diffmap import (
        _strays_from_parsed, _uninspectable_from_parsed,
        find_ambiguous_files, map_files_to_entity_ids, normalize_path,
        parse_unified_diff,
    )
    from verifyci.verification.partition import classify_path, FilePartition

    explanation = cert.conclusion.reasoning
    code_files = [f for f in files if classify_path(f) == FilePartition.CODE_CORE]
    ambiguous = find_ambiguous_files(code_files, entities or [])
    if ambiguous:
        details = ", ".join(f"{f} ({len(p)} paths)" for f, p in sorted(ambiguous.items()))
        explanation = f"{explanation}; suffix-ambiguous grounding: {details}"
    ent_paths = {normalize_path(getattr(e, "file_path", "") or "")
                 for e in entities or []}
    try:
        mapping = map_files_to_entity_ids(code_files, entities or [])
    except Exception:  # noqa: BLE001
        mapping = {}
    suffix_only = sorted(
        f for f in code_files
        if mapping.get(f) and normalize_path(f) not in ent_paths
    )
    if suffix_only:
        explanation = (f"{explanation}; suffix-only grounding "
                       f"(no exact stored path): {', '.join(suffix_only)}")
    opaque: list[str] = []
    uncovered: list[str] = []
    stray_uncovered: list[str] = []
    if diff is not None:
        # One parse serves all three diff projections (opaque, uncovered,
        # strays): O(D) instead of O(3D).
        parsed = parse_unified_diff(diff)
        opaque = sorted(_uninspectable_from_parsed(parsed))
        if opaque:
            explanation = (f"{explanation}; opaque change (content not in "
                            f"diff): {', '.join(opaque)}")
        uncovered = sorted(_uncovered_from_parsed(parsed, entities or []))
        if uncovered:
            explanation = (f"{explanation}; changed lines outside every "
                           f"entity span: {', '.join(uncovered[:8])}")
        stray_uncovered = sorted(
            f for f in _strays_from_parsed(parsed)
            if classify_path(f) == FilePartition.CODE_CORE
        )
        if stray_uncovered:
            explanation = (f"{explanation}; unpositioned change outside any "
                           f"hunk (stray +/- lines): {', '.join(stray_uncovered)}")
    established = (not ambiguous and not suffix_only and not opaque
                   and not uncovered and not stray_uncovered)
    return CheckResult(
        check_id="semi_formal",
        passed=cert.certificate_verified,
        score=cert.confidence,
        evidence=[e.file_path for e in cert.evidence],
        explanation=explanation,
        established=established,
        # The certificate travels with the check so policy can tell
        # inability (unverified cert → INCONCLUSIVE) from rejection
        # (failed check on a verified cert → FAIL). Without it every
        # grounding failure read as a rejection.
        certificate=cert,
    )


def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping and contiguous entity spans into disjoint sorted intervals."""
    if not spans:
        return []
    sorted_spans = sorted(spans)
    merged = [sorted_spans[0]]
    for s, en in sorted_spans[1:]:
        prev_s, prev_en = merged[-1]
        if s <= prev_en:
            merged[-1] = (prev_s, max(prev_en, en))
        else:
            merged.append((s, en))
    return merged


def _uncovered_from_parsed(parsed: list, entities: list) -> list[str]:
    """_uncovered_changed_lines over an already-parsed diff (parse once).

    Span geometry untouched: same per-line anchors, same decorator and
    import adjacency grace, same order-preserving duplicate collapse.
    """
    from verifyci.verification.diffmap import normalize_path
    from verifyci.verification.partition import classify_path, FilePartition

    raw_spans: dict[str, list[tuple[int, int]]] = {}
    for e in entities:
        t = getattr(e, "type", None)
        if t is not None and str(getattr(t, "value", t)) == "MODULE":
            continue
        p = normalize_path(getattr(e, "file_path", "") or "")
        if not p:
            continue
        try:
            s = int(getattr(e, "line_start", 1) or 1)
            en = int(getattr(e, "line_end", s) or s)
        except (TypeError, ValueError):
            continue
        raw_spans.setdefault(p, []).append((s, en))

    merged_spans: dict[str, list[tuple[int, int]]] = {}
    span_starts: dict[str, list[int]] = {}
    decorator_starts: dict[str, set[int]] = {}
    import_endpoints: dict[str, list[int]] = {}

    for p, span_list in raw_spans.items():
        merged = _merge_spans(span_list)
        merged_spans[p] = merged
        span_starts[p] = [s for s, _ in merged]
        decorator_starts[p] = {s - 1 for s, _ in span_list}
        import_endpoints[p] = sorted({s for s, _ in span_list} | {en for _, en in span_list})

    out: list[str] = []
    seen: set[str] = set()
    # Same anchor geometry as changed_line_anchor_sets (a `-` line anchors
    # its own old line; a `+` anchors the insertion point), recomputed
    # here so the adjacency grace can see the changed line's content.
    for f in parsed:
        file_path = f.path
        if file_path is None:
            continue
        if classify_path(file_path) != FilePartition.CODE_CORE:
            continue
        norm_f = normalize_path(file_path)
        file_spans = merged_spans.get(norm_f, [])
        file_starts = span_starts.get(norm_f, [])
        file_dec_starts = decorator_starts.get(norm_f)
        file_endpoints = import_endpoints.get(norm_f, [])
        for h in f.hunks:
            old_ln = h.old_start
            prev_minus = False
            for body in h.lines:
                if body.startswith("\\"):
                    continue
                if body.startswith("-"):
                    anchors = {old_ln}
                    content = body[1:]
                    old_ln += 1
                    prev_minus = True
                elif body.startswith("+"):
                    if prev_minus:
                        anchors = {old_ln - 1} if old_ln > 1 else {old_ln}
                    else:
                        anchors = {old_ln}
                        if old_ln > 1:
                            anchors.add(old_ln - 1)
                    content = body[1:]
                else:
                    old_ln += 1
                    prev_minus = False
                    continue
                coverable = sorted(ln for ln in anchors if ln > 0)
                if not coverable:
                    continue  # positionless content (new-file `+` at old
                    # line 0): nothing to attribute; ungrounded-file and
                    # opaque checks own that case.
                if any(_anchor_covered(ln, file_spans, file_starts, content, file_dec_starts, file_endpoints) for ln in coverable):
                    continue
                key = f"{file_path}:{coverable[0]}"
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    return out



def _uncovered_changed_lines(diff: str, entities: list) -> list[str]:
    """Changed lines in CODE_CORE files that fall outside any entity span.

    File-level grounding (the certificate seeds a whole file) used to
    let an edit to a module constant, flag, import, or decorator PASS
    on the back of unrelated entities in the same file, with blast
    radius 0. Every changed LINE must have at least one old-side
    anchor inside some non-MODULE entity span, else the check reports
    established=False (INCONCLUSIVE at policy — inability, never a
    pass on unseen code). Per-line (not per-anchor): a tail insertion
    at a function's last line straddles the span edge by construction
    (the A2 geometry), so one covered anchor covers the line.

    Decorator adjacency: extractor spans start at `def`/`class`
    (extractor.py is frozen by the latency guard, so the span fix lives
    here, not there); a changed line exactly one line above a span start
    is the decorated definition's decorator — but ONLY when the changed
    line itself is a decorator (`@...`). Any other line one above a span
    (a module constant, flag, or stray statement) is uncovered.

    Duplicate `path:line` anchors collapse preserving order: a
    replacement pair (`-` then `+`) anchors the same old line twice but
    reports one uncovered item.
    """
    from verifyci.verification.diffmap import parse_unified_diff
    return _uncovered_from_parsed(parse_unified_diff(diff), entities)


def _anchor_covered(
    ln: int,
    file_spans: list[tuple[int, int]],
    starts: list[int] | None = None,
    content: str = "",
    dec_starts: set[int] | None = None,
    endpoints: list[int] | None = None,
) -> bool:
    if file_spans:
        if starts is not None and len(starts) == len(file_spans):
            idx = bisect_right(starts, ln) - 1
            if idx >= 0:
                s, en = file_spans[idx]
                if s <= ln <= en:
                    return True
        else:
            for s, en in file_spans:
                if s <= ln <= en:
                    return True
                if s > ln:
                    break

    # One line above a span start is only the decorator when the changed
    # line is itself a decorator line.
    if content.lstrip().startswith("@"):
        if dec_starts is not None:
            return ln in dec_starts
        return any(s - ln == 1 for s, en in file_spans)

    # An import statement added adjacent to an existing import/code entity span
    if content.lstrip().startswith(("import ", "from ")):
        if endpoints:
            idx = bisect_left(endpoints, ln)
            if idx < len(endpoints) and abs(endpoints[idx] - ln) <= 2:
                return True
            if idx > 0 and abs(endpoints[idx - 1] - ln) <= 2:
                return True
            return False
        return any(abs(s - ln) <= 2 or abs(en - ln) <= 2 for s, en in file_spans)
    return False


def build_verification_report(
    task_id: str,
    policy_id: str,
    checks: list[CheckResult],
    blast_radius: BlastRadiusResult,
) -> VerificationReport:
    return VerificationReport(
        report_id=str(uuid.uuid4()),
        task_id=task_id,
        policy_id=policy_id,
        checks=checks,
        blast_radius=blast_radius,
        timestamp=time.time(),
    )
