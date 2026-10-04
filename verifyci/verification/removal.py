"""Removal provenance: every `-` line must have existed where claimed.

A diff claiming to delete code that was never at those lines in the base
revision is stale, hallucinated, or forged - fail closed (FAIL), not
INCONCLUSIVE. Verified removals of known code stay exactly where the
deletion tripwire puts them (INCONCLUSIVE: behavior not verified); this
checker judges provenance, never intent.

Matching is line-by-line against stored entity snippets at the hunk old-side
offsets, exact content (both sides come from `splitlines`, so newline style
cannot mismatch). Three outcomes per removed line:
- verified: inside a code entity whose stored snippet completely covers
  the entity span, content equal at that offset;
- fabricated: inside a completely-covered span, content differs - the
  stored record positively contradicts the diff;
- unverified: outside all entity spans (comments, headers, blank gaps),
  inside a truncated snippet, covered only by snippet-less rows
  (PARAMETERs, MODULEs), in an approximate (`@@@`) hunk, or outside any
  hunk at all. Absence of record is not contradiction: unverified routes
  to inability (established=False -> INCONCLUSIVE), never FAIL.
"""
import unicodedata

from verifyci.contracts.entity import EntitySnippetRecord
from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import (
    iter_hunks,
    normalize_path,
    unattributed_removed_lines,
)


def _normalize_line(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _repair_mojibake(text: str) -> str | None:
    """Attempt cp1252 -> utf-8 repair.

    Residual risk:
    Accepts decode(cp1252) -> encode(utf-8) in either direction in `_lines_match`.
    If a removed diff line L1 happens to be a cp1252-misdecoded form of a distinct
    line L2 in the snippet record, the two lines will match. This heuristic tolerates
    Windows/PowerShell console encoding corruptions, but creates a rare residual risk
    of false-verified removal provenance if distinct lines coincide under mojibake
    inversion.
    """
    try:
        return text.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return None


def _lines_match(line_a: str, line_b: str) -> bool:
    norm_a = _normalize_line(line_a)
    norm_b = _normalize_line(line_b)
    if norm_a == norm_b:
        return True
    rep_a = _repair_mojibake(norm_a)
    if rep_a is not None and _normalize_line(rep_a) == norm_b:
        return True
    rep_b = _repair_mojibake(norm_b)
    if rep_b is not None and _normalize_line(rep_b) == norm_a:
        return True
    return False


def _is_code(entity) -> bool:
    t = getattr(entity, "type", None)
    if t is None:
        return True
    return str(getattr(t, "value", t)) != "MODULE"


def _snippet_record(entity) -> EntitySnippetRecord | None:
    from verifyci.ingestion.extractor import _split_source_lines

    meta = getattr(entity, "metadata", None) or {}
    snippet = meta.get("snippet")
    if not snippet:
        return None

    slices = meta.get("slices") or []
    if slices:
        if slices[0] == snippet:
            full_text = "".join(slices)
        else:
            full_text = str(snippet) + "".join(slices)
    else:
        full_text = str(snippet)

    raw_lines = _split_source_lines(full_text.encode("utf-8", errors="replace"))
    start = getattr(entity, "line_start", 1) or 1
    end = getattr(entity, "line_end", start) or start
    span = end - start + 1
    if len(raw_lines) == span + 1 and raw_lines[-1] == "":
        raw_lines = raw_lines[:-1]

    if "snippet_is_complete" in meta:
        is_complete = bool(meta["snippet_is_complete"])
        truncated_at_line = meta.get("snippet_truncated_at_line")
        return EntitySnippetRecord(
            lines=raw_lines,
            is_complete=is_complete,
            truncated_at_line=truncated_at_line,
            char_count=len(full_text),
            encoding="utf-8",
        )

    # Legacy fallback for entities without explicit completeness metadata:
    if len(raw_lines) < span:
        return EntitySnippetRecord(
            lines=raw_lines,
            is_complete=False,
            truncated_at_line=start + len(raw_lines),
            char_count=len(snippet),
            encoding="utf-8",
        )

    if len(str(snippet)) >= 2000:
        return EntitySnippetRecord(
            lines=raw_lines,
            is_complete=False,
            truncated_at_line=end,
            char_count=len(snippet),
            encoding="utf-8",
        )

    return EntitySnippetRecord(
        lines=raw_lines,
        is_complete=True,
        truncated_at_line=None,
        char_count=len(snippet),
        encoding="utf-8",
    )


def _snippet_lines(entity) -> list[str] | None:
    rec = _snippet_record(entity)
    return rec.lines if rec else None


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
    approx_unverified = 0
    fabricated: list[str] = []
    for hunk in hunks:
        if getattr(hunk, "approximate", False):
            for body in hunk.lines:
                stripped = body.lstrip()
                if body.startswith("\\") or stripped.startswith("\\"):
                    continue
                if stripped.startswith("+"):
                    continue
                if not stripped.startswith("-"):
                    continue
                unverified += 1
                approx_unverified += 1
            continue
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

    stray_lines = unattributed_removed_lines(diff)
    stray = len(stray_lines)
    unverified += stray

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
        stray_total = approx_unverified + stray
        detail = f"verified={verified} unverified={unverified} "
        detail += "(outside entity spans or truncated snippets"
        if stray_total:
            detail += f"; {stray_total} stray/approximate removed lines"
        detail += ")"
        return CheckResult(
            check_id="removal_provenance",
            passed=True,
            score=round(verified / total, 3),
            evidence=[],
            explanation=detail,
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
    """One removed line: verified / fabricated / unverified.

    According to Contract 3:
    - verified: inside a code entity whose stored snippet covers the line,
      content equal at that offset (with NFC normalization and mojibake resilience).
    - fabricated: inside an entity with is_complete == True, content differs.
    - unverified: outside all entities, inside a truncated snippet at or beyond
      truncation, or in incomplete/missing entities.
    """
    if not file:
        return "unverified"
    complete_hits = 0
    for entity in candidates:
        start = getattr(entity, "line_start", 1) or 1
        end = getattr(entity, "line_end", start) or start
        if not (start <= old_ln <= end):
            continue
        rec = _snippet_record(entity)
        if not rec:
            continue

        offset = old_ln - start
        if 0 <= offset < len(rec.lines) and _lines_match(rec.lines[offset], content):
            return "verified"

        # Check if this entity's snippet is complete:
        # If is_complete is False, it cannot claim fabrication.
        if rec.is_complete:
            complete_hits += 1

    if complete_hits:
        return "fabricated"
    return "unverified"