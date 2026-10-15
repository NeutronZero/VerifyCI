"""Diff impact: which symbols a diff touches, and what transitively depends on them.

Two stages, both fail-closed on identity:

1. **Seed extraction.** A diff hunk marks the entities whose line spans it
   overlaps. File identity is compared exactly. A suffix match would let
   `auth/client_1.py` inherit the record for `api/client_1.py`, which the
   `same_basename_collisions` slice exists to catch.
2. **Impact closure.** Impact is the set of symbols that can *reach* a seed,
   walking reversed call edges. A seed is never its own impact.
"""
from __future__ import annotations
import msgspec
import re
from typing import Any, Iterable
_HUNK_RE = re.compile('^@@+ -(\\d+)(?:,(\\d+))? \\+(\\d+)(?:,(\\d+))? @@+')
_RENAME_FROM_RE = re.compile('^rename from (.+)$')
_RENAME_TO_RE = re.compile('^rename to (.+)$')

class HunkSpan(msgspec.Struct, frozen=True, kw_only=True):
    """A hunk's touched line ranges on the old and new sides (1-based, inclusive)."""
    old_start: int
    old_count: int
    new_start: int
    new_count: int

class FileHunk(msgspec.Struct, frozen=True, kw_only=True):
    old_path: str
    new_path: str
    spans: tuple[HunkSpan, ...]

class DiffImpact(msgspec.Struct, frozen=True, kw_only=True):
    seeds: tuple[str, ...]
    impact: tuple[str, ...]
    unattributed_files: tuple[str, ...]

def _clean(path: str) -> str:
    cleaned = path.strip().split('\t')[0].replace('\\', '/')
    for prefix in ('a/', 'b/'):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
    return cleaned.lstrip('./')

def parse_file_hunks(diff: str) -> tuple[FileHunk, ...]:
    """Splits a unified diff into per-file hunk spans, following renames."""
    out: list[tuple[str, str, list[HunkSpan]]] = []
    old_path = new_path = ''
    rename_from = ''
    spans: list[HunkSpan] = []

    def flush() -> None:
        if (old_path or new_path) and spans:
            out.append((old_path, new_path, list(spans)))
    for line in diff.splitlines():
        rename_match = _RENAME_FROM_RE.match(line)
        if rename_match:
            rename_from = _clean(rename_match.group(1))
            continue
        rename_match = _RENAME_TO_RE.match(line)
        if rename_match:
            new_path = _clean(rename_match.group(1))
            if not old_path:
                old_path = rename_from
            continue
        if line.startswith('--- '):
            flush()
            spans = []
            rename_from = ''
            old_path = '' if line[4:].startswith('/dev/null') else _clean(line[4:])
            new_path = ''
            continue
        if line.startswith('+++ '):
            new_path = '' if line[4:].startswith('/dev/null') else _clean(line[4:])
            continue
        hunk = _HUNK_RE.match(line)
        if hunk:
            spans.append(HunkSpan(old_start=int(hunk.group(1)), old_count=int(hunk.group(2) or 1), new_start=int(hunk.group(3)), new_count=int(hunk.group(4) or 1)))
    flush()
    return tuple((FileHunk(old_path=old, new_path=new, spans=tuple(s)) for old, new, s in out))

def _entity_span(entity: dict[str, Any]) -> tuple[int, int]:
    return (int(entity.get('line_start', 0)), int(entity.get('line_end', -1)))

def _span_overlaps(entity_start: int, entity_end: int, low: int, high: int) -> bool:
    if high < low:
        return False
    return entity_start <= high and low <= entity_end

def seed_entities(diff: str, entities: Iterable[dict[str, Any]]) -> tuple[set[str], set[str]]:
    """Returns (seed ids, file paths the diff touched but no entity covers).

    A hunk is attributed on whichever side has lines. Both the old and new path
    are considered so a rename still attributes to the entity recorded under
    its post-rename location.
    """
    entity_list = list(entities)
    seeds: set[str] = set()
    attributed_files: set[str] = set()
    for file_hunk in parse_file_hunks(diff):
        for entity in entity_list:
            entity_path = _clean(str(entity.get('file_path', '')))
            if entity_path not in (file_hunk.old_path, file_hunk.new_path):
                continue
            entity_start, entity_end = _entity_span(entity)
            if entity_end < entity_start:
                continue
            touched = False
            for span in file_hunk.spans:
                if span.new_count > 0 and _span_overlaps(entity_start, entity_end, span.new_start, span.new_start + span.new_count - 1):
                    touched = True
                    break
                if span.old_count > 0 and _span_overlaps(entity_start, entity_end, span.old_start, span.old_start + span.old_count - 1):
                    touched = True
                    break
            if touched:
                seeds.add(str(entity.get('revision_entity_id', '')))
                attributed_files.add(entity_path)
    diff_files = {path for hunk in parse_file_hunks(diff) for path in (hunk.old_path, hunk.new_path) if path}
    unattributed = diff_files - attributed_files
    return (seeds, unattributed)

def impact_of(seeds: Iterable[str], graph_edges: Iterable[Iterable[str]]) -> set[str]:
    """Symbols that transitively reach any seed, excluding the seeds."""
    seed_set = set(seeds)
    reverse: dict[str, set[str]] = {}
    for edge in graph_edges:
        pair = list(edge)
        if len(pair) != 2:
            continue
        src, dst = (str(pair[0]), str(pair[1]))
        reverse.setdefault(dst, set()).add(src)
    reached: set[str] = set()
    frontier = list(seed_set)
    while frontier:
        node = frontier.pop()
        for caller in reverse.get(node, ()):
            if caller in reached or caller in seed_set:
                continue
            reached.add(caller)
            frontier.append(caller)
    return reached

def analyze_diff_impact(diff: str, entities: Iterable[dict[str, Any]], graph_edges: Iterable[Iterable[str]]) -> DiffImpact:
    seeds, unattributed = seed_entities(diff, entities)
    impact = impact_of(seeds, graph_edges)
    return DiffImpact(seeds=tuple(sorted(seeds)), impact=tuple(sorted(impact)), unattributed_files=tuple(sorted(unattributed)))
