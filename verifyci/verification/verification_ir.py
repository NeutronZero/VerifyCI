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
        find_ambiguous_files, map_files_to_entity_ids, normalize_path,
        uninspectable_files, files_with_stray_lines,
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
    if diff is not None:
        opaque = sorted(uninspectable_files(diff))
        if opaque:
            explanation = (f"{explanation}; opaque change (content not in "
                            f"diff): {', '.join(opaque)}")
    uncovered: list[str] = []
    if diff is not None:
        uncovered = sorted(_uncovered_changed_lines(diff, entities or []))
        if uncovered:
            explanation = (f"{explanation}; changed lines outside every "
                           f"entity span: {', '.join(uncovered[:8])}")
    stray_uncovered: list[str] = []
    if diff is not None:
        stray_uncovered = sorted(
            f for f in files_with_stray_lines(diff)
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


def _uncovered_changed_lines(diff: str, entities: list) -> list[str]:
    """Changed lines no code entity spans: `path:line` items.

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
    from verifyci.verification.diffmap import (
        iter_hunks, normalize_path,
    )
    from verifyci.verification.partition import classify_path, FilePartition

    spans: dict[str, list[tuple[int, int]]] = {}
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
        spans.setdefault(p, []).append((s, en))
    out: list[str] = []
    seen: set[str] = set()
    # Same anchor geometry as changed_line_anchor_sets (a `-` line anchors
    # its own old line; a `+` anchors the insertion point), recomputed
    # here so the adjacency grace can see the changed line's content.
    for h in iter_hunks(diff):
        if h.file is None:
            continue
        if classify_path(h.file) != FilePartition.CODE_CORE:
            continue
        file_spans = spans.get(normalize_path(h.file), [])
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
            if any(_anchor_covered(ln, file_spans, content) for ln in coverable):
                continue
            key = f"{h.file}:{coverable[0]}"
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _anchor_covered(ln: int, file_spans: list[tuple[int, int]], content: str = "") -> bool:
    if any(s <= ln <= en for s, en in file_spans):
        return True
    # One line above a span start is only the decorator when the changed
    # line is itself a decorator line.
    if content.lstrip().startswith("@"):
        return any(s - ln == 1 for s, en in file_spans)
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
