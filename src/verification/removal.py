"""Removal provenance: every `-` line must have existed where claimed.

A diff claiming to delete code that was never at those lines in the base
revision is stale, hallucinated, or forged — fail closed (FAIL), not
INCONCLUSIVE. Verified removals of known code stay exactly where the
deletion tripwire puts them (INCONCLUSIVE: behavior not verified); this
checker judges provenance, never intent.

Matching is line-by-line against stored entity snippets at the hunk's
old-side offsets, exact content (both sides come from `splitlines`, so
newline style cannot mismatch). Three outcomes per removed line:
- verified: inside a code entity whose stored snippet completely covers
  the entity span, content equal at that offset;
- fabricated: inside a completely-covered span, content differs — the
  stored record positively contradicts the diff;
- unverified: outside all entity spans (comments, headers, blank gaps),
  inside a truncated snippet, covered only by snippet-less rows
  (PARAMETERs, MODULEs), or in a file with no entities at all.
  Absence of record is not contradiction: unverified routes to
  inability (established=False → INCONCLUSIVE), never FAIL.
"""
from src.contracts.verification_ir import CheckResult
from src.verification.diffmap import iter_hunks, normalize_path


def _is_code(entity) -> bool:
    t = getattr(entity, "type", None)
    if t is None:
        return True
    return str(getattr(t, "value", t)) != "MODULE"


def _snippet_lines(entity) -> list[str] | None:
    meta = getattr(entity, "metadata", None) or {}
    snippet = meta.get("snippet")
    if not snippet:
        return None
    return str(snippet).splitlines()


def removal_provenance_check(diff: str | None, entities: list) -> CheckResult:
    """Check removed lines against stored base-revision content."""
    hunks = iter_hunks(diff)
    records: list[tuple[str, object]] = []
    for entity in entities or []:
        if not _is_code(entity):
            continue
        path = normalize_path(getattr(entity, "file_path", "") or "")
        if path:
            records.append((path, entity))

    def _covering(diff_file: str) -> list:
        want = normalize_path(diff_file or "")
        if not want:
            return []
        return [e for epath, e in records
                if epath == want or epath.endswith("/" + want)
                or want.endswith("/" + epath)]

    verified = unverified = 0
    fabricated: list[str] = []
    for hunk in hunks:
        old_ln = hunk.old_start
        for body in hunk.lines:
            if body.startswith("+") or body.startswith("\\"):
                continue
            if not body.startswith("-"):
                old_ln += 1
                continue
            content = body[1:]
            verdict = _classify_removed(
                hunk.file, old_ln, content, _covering(hunk.file or ""))
            if verdict == "verified":
                verified += 1
            elif verdict == "fabricated":
                fabricated.append(f"{hunk.file}:{old_ln}")
            else:
                unverified += 1
            old_ln += 1

    total = verified + unverified + len(fabricated)
    if total == 0:
        return CheckResult(
            check_id="removal_provenance",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="no removed lines",
        )
    if fabricated:
        first = fabricated[0]
        rest = f" +{len(fabricated) - 1} more" if len(fabricated) > 1 else ""
        return CheckResult(
            check_id="removal_provenance",
            passed=False,
            score=round(verified / total, 3),
            evidence=list(fabricated),
            explanation=f"removed lines contradict stored content at {first}{rest}",
        )
    if unverified:
        return CheckResult(
            check_id="removal_provenance",
            passed=True,
            score=round(verified / total, 3),
            evidence=[],
            explanation=f"verified={verified} unverified={unverified} "
                        f"(outside entity spans or truncated snippets)",
            established=False,
        )
    return CheckResult(
        check_id="removal_provenance",
        passed=True,
        score=1.0,
        evidence=[],
        explanation=f"verified={verified} removed lines against stored content",
    )


def _classify_removed(file: str | None, old_ln: int, content: str,
                       candidates: list) -> str:
    """One removed line: verified / fabricated / unverified."""
    if not file:
        return "unverified"
    complete_hits = 0
    for entity in candidates:
        start = getattr(entity, "line_start", 1) or 1
        end = getattr(entity, "line_end", start) or start
        if not (start <= old_ln <= end):
            continue
        lines = _snippet_lines(entity)
        if not lines:
            continue
        span = end - start + 1
        if len(lines) < span:
            continue  # truncated snippet: record too partial to contradict
        complete_hits += 1
        if 0 <= old_ln - start < len(lines) and lines[old_ln - start] == content:
            return "verified"
    if complete_hits:
        return "fabricated"
    return "unverified"
