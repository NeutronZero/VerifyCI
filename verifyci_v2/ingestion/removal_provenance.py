"""Removal provenance: every `-` line must have existed where the diff claims.

A diff that deletes code which was never at those lines in the base revision is
stale, hallucinated, or forged. This checker judges provenance only, never
intent, and assigns one of three outcomes per removed line:

- ``VERIFIED``     inside a completely-covered entity span whose stored snippet
                   matches the removed content at that offset.
- ``FABRICATED``   inside a completely-covered span but the content differs, so
                   the stored record positively contradicts the diff.
- ``UNVERIFIED``   no provenance for the path, outside every entity span, a
                   truncated snippet, a snippet-less record, or an approximate
                   (``@@@``) hunk.

Absence of a record is not contradiction, so ``UNVERIFIED`` routes to
INCONCLUSIVE and never to FABRICATED.
"""

from __future__ import annotations

import msgspec
import re
import unicodedata
from typing import Any

VERDICT_ORDER = ("VERIFIED", "INCONCLUSIVE", "FABRICATED")

_HUNK_RE = re.compile(r"^@@+ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@+")

# Entity types that carry no source span.
_SNIPPETLESS_TYPES = frozenset({"PARAMETER", "MODULE", "IMPORT", "FILE"})


class RemovedLine(msgspec.Struct, frozen=True, kw_only=True):
    """A removed line with its resolved old-side line number.

    The line number must account for preceding context lines in the hunk, so it
    is tracked during parsing rather than derived from the removal index.
    """

    line_no: int
    content: str


class Hunk(msgspec.Struct, frozen=True, kw_only=True):
    file_path: str
    approximate: bool
    old_start: int
    removed: tuple[RemovedLine, ...]


class RemovalProvenance(msgspec.Struct, frozen=True, kw_only=True):
    verdict: str
    verified_lines: int
    fabricated_lines: int
    unverified_lines: int
    reasons: tuple[str, ...]


def normalize_path(path: str) -> str:
    """Strips git's a/ b/ prefix. Paths compare exactly: a suffix match would
    let `app/models.py` inherit the record for `models.py`."""
    cleaned = path.strip().replace("\\", "/")
    for prefix in ("a/", "b/"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
    return cleaned.lstrip("./")


def parse_hunks(diff: str) -> list[Hunk]:
    """Parses unified diffs into hunks, retaining old-side line offsets."""
    pending: list[tuple[str, bool, int, list[RemovedLine]]] = []
    current_path: str | None = None
    old_line = 0
    current_index: int | None = None

    for line in diff.splitlines():
        if line.startswith("--- "):
            current_path = normalize_path(line[4:].split("\t")[0])
            current_index = None
            continue
        if line.startswith("+++ "):
            new_path = normalize_path(line[4:].split("\t")[0])
            if new_path != "/dev/null":
                current_path = new_path
            current_index = None
            continue

        match = _HUNK_RE.match(line)
        if match and current_path is not None:
            old_line = int(match.group(1))
            pending.append((current_path, line.startswith("@@@"), old_line, []))
            current_index = len(pending) - 1
            continue

        if current_index is None:
            continue
        if line.startswith("-"):
            pending[current_index][3].append(
                RemovedLine(line_no=old_line, content=line[1:])
            )
            old_line += 1
        elif line.startswith("+"):
            continue
        elif line.startswith(" ") or line == "":
            old_line += 1

    return [
        Hunk(
            file_path=path,
            approximate=approximate,
            old_start=old_start,
            removed=tuple(removed),
        )
        for path, approximate, old_start, removed in pending
    ]


def _repair_mojibake(text: str) -> str | None:
    try:
        return text.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return None


def _lines_match(left: str, right: str) -> bool:
    a = unicodedata.normalize("NFC", left)
    b = unicodedata.normalize("NFC", right)
    if a == b:
        return True
    if a.strip() and a.strip() == b.strip():
        return True
    for first, second in ((a, b), (b, a)):
        repaired = _repair_mojibake(first)
        if repaired is not None:
            if unicodedata.normalize("NFC", repaired).strip() == second.strip():
                return True
    return False


def _entity_records(
    entities: list[dict[str, Any]], file_path: str
) -> list[dict[str, Any]]:
    return [
        e
        for e in entities
        if normalize_path(str(e.get("file_path", ""))) == file_path
    ]


def entities_from_source(
    file_path: str,
    source: str,
    *,
    prelowered_funcs: tuple[Any, ...] | None = None,
) -> list[dict[str, Any]]:
    """Build provenance records from a trusted base source and lowered functions.

    The pipeline supplies ``prelowered_funcs`` from its ``CompiledFilePair`` so
    provenance reuses the same base compilation rather than parsing/lowering a
    revision a second time. Standalone compatibility callers may omit it.
    """
    if not source.strip():
        return []
    if prelowered_funcs is None:
        from verifyci_v2.ingestion.ssa_lower import lower_file_to_ussa
        try:
            functions = lower_file_to_ussa(file_path, source, language="python")
        except Exception:
            return []
    else:
        functions = prelowered_funcs

    lines = source.splitlines()
    entities: list[dict[str, Any]] = []
    for func in functions:
        start = max(1, func.start_line)
        end = min(len(lines), func.end_line)
        if end < start:
            continue
        entities.append(
            {
                "file_path": file_path,
                "line_start": start,
                "line_end": end,
                "type": "FUNCTION",
                "metadata": {
                    "snippet": "\n".join(lines[start - 1 : end]),
                    "snippet_is_complete": True,
                },
            }
        )
    return entities


def analyze_removal_provenance(
    diff: str, entities: list[dict[str, Any]]
) -> RemovalProvenance:
    """Classifies every removed line in `diff` against the stored entity records."""
    hunks = parse_hunks(diff)
    verified = fabricated = unverified = 0
    reasons: list[str] = []

    entities_by_path: dict[str, list[dict[str, Any]]] = {}
    for e in entities:
        norm_p = normalize_path(str(e.get("file_path", "")))
        if norm_p:
            entities_by_path.setdefault(norm_p, []).append(e)

    for hunk in hunks:
        file_entities = entities_by_path.get(hunk.file_path, [])
        if not file_entities:
            unverified += len(hunk.removed)
            reasons.append(
                f"no provenance for '{hunk.file_path}'; cannot verify removal"
            )
            continue

        if hunk.approximate:
            unverified += len(hunk.removed)
            reasons.append(
                f"approximate hunk in '{hunk.file_path}' has no stable offsets"
            )
            continue

        for removed in hunk.removed:
            outcome, why = _classify_line(
                removed.content, removed.line_no, file_entities, hunk.file_path
            )
            if outcome == "VERIFIED":
                verified += 1
            elif outcome == "FABRICATED":
                fabricated += 1
                reasons.append(
                    f"{hunk.file_path}:{removed.line_no}: stored snippet "
                    f"contradicts the removed line ({why})"
                )
            else:
                unverified += 1
                reasons.append(f"{hunk.file_path}:{removed.line_no}: {why}")

    verdict = "VERIFIED"
    for candidate in ("INCONCLUSIVE", "FABRICATED"):
        if candidate == "FABRICATED" and fabricated:
            verdict = "FABRICATED"
        elif candidate == "INCONCLUSIVE" and unverified and verdict == "VERIFIED":
            verdict = "INCONCLUSIVE"
    if fabricated:
        verdict = "FABRICATED"

    return RemovalProvenance(
        verdict=verdict,
        verified_lines=verified,
        fabricated_lines=fabricated,
        unverified_lines=unverified,
        reasons=tuple(reasons[:8]),
    )


def _classify_line(
    content: str,
    line_no: int,
    entities: list[dict[str, Any]],
    file_path: str,
) -> tuple[str, str]:
    """Returns (outcome, reason) for a single removed line."""
    covering = [
        e
        for e in entities
        if int(e.get("line_start", 0)) <= line_no <= int(e.get("line_end", -1))
    ]
    if not covering:
        return "UNVERIFIED", "line falls outside every known entity span"

    snippetless = [e for e in covering if str(e.get("type")) in _SNIPPETLESS_TYPES]
    if snippetless and len(snippetless) == len(covering):
        return "UNVERIFIED", f"record has no source snippet ({snippetless[0].get('type')})"

    incomplete = [
        e for e in covering if not e.get("metadata", {}).get("snippet_is_complete")
    ]
    if incomplete and len(incomplete) == len(covering):
        return "UNVERIFIED", "stored snippet is truncated"

    # Nested scopes produce overlapping records. The line is verified if ANY
    # completely-covered record agrees; FABRICATED only when every one of them
    # positively contradicts it.
    contradiction: str | None = None
    for entity in covering:
        metadata = entity.get("metadata", {})
        snippet = metadata.get("snippet")
        if not snippet:
            continue
        if not metadata.get("snippet_is_complete"):
            continue
        snippet_lines = metadata.get("_split_lines")
        if snippet_lines is None:
            snippet_lines = snippet.splitlines()
            metadata["_split_lines"] = snippet_lines
        offset = line_no - int(entity.get("line_start", 0))
        if offset < 0 or offset >= len(snippet_lines):
            continue
        if _lines_match(content, snippet_lines[offset]):
            return "VERIFIED", "content matches the stored snippet"
        contradiction = (
            f"stored snippet has {snippet_lines[offset]!r} at this offset"
        )

    if contradiction is not None and not incomplete:
        return "FABRICATED", contradiction

    return "UNVERIFIED", "no complete stored snippet covers this line"