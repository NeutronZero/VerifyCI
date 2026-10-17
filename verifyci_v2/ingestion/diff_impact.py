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
from collections import deque
from typing import Any, Iterable, Sequence
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
    file_hunks = parse_file_hunks(diff)
    if not file_hunks:
        return (set(), set())

    entities_by_path: dict[str, list[dict[str, Any]]] = {}
    for entity in entities:
        path = _clean(str(entity.get('file_path', '')))
        if path:
            entities_by_path.setdefault(path, []).append(entity)

    seeds: set[str] = set()
    attributed_files: set[str] = set()
    diff_files: set[str] = set()

    for file_hunk in file_hunks:
        for p in (file_hunk.old_path, file_hunk.new_path):
            if p:
                diff_files.add(p)

        target_paths: set[str] = set()
        if file_hunk.old_path in entities_by_path:
            target_paths.add(file_hunk.old_path)
        if file_hunk.new_path in entities_by_path:
            target_paths.add(file_hunk.new_path)

        for path in target_paths:
            for entity in entities_by_path[path]:
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
                    attributed_files.add(path)

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

# --------------------------------------------------------------------------
# Hop-bounded semantic blast radius over a raw typed graph (cap007).
#
# `impact_of` answers an unbounded question on symbol pairs. This section
# answers the *bounded, edge-type-filtered* question the protocol defines, and
# returns a deterministic ranking so retrieval order is reproducible.
# --------------------------------------------------------------------------

# Traversable semantic edge types per MODE_PROTOCOL.md. An edge whose type is
# outside this set is not semantic reachability and must not extend a blast
# radius.
CALL_FLOW_EDGE_TYPES = frozenset({'CALLS', 'IMPORTS', 'INHERITS', 'DEPENDS_ON'})

class Graph(msgspec.Struct, frozen=True, kw_only=True):
    """An indexed typed graph: adjacency in both directions plus raw edges."""
    nodes: dict[str, dict[str, Any]]
    outgoing: dict[str, tuple[tuple[str, str], ...]]
    incoming: dict[str, tuple[tuple[str, str], ...]]
    edges: tuple[dict[str, Any], ...]

class BlastRadius(msgspec.Struct, frozen=True, kw_only=True):
    affected_callers: tuple[str, ...]
    affected_callees: tuple[str, ...]
    impacted: tuple[str, ...]
    coverage_gap: tuple[str, ...]
    risk_score: float
    dependency_packages: tuple[str, ...]
    hop_distances: dict[str, int]

def build_graph(nodes: Iterable[dict[str, Any]], edges: Iterable[dict[str, Any]]) -> Graph:
    node_map = {str(n['id']): n for n in nodes}
    out: dict[str, list[tuple[str, str]]] = {nid: [] for nid in node_map}
    inc: dict[str, list[tuple[str, str]]] = {nid: [] for nid in node_map}
    edge_list = list(edges)
    for e in edge_list:
        src, dst = str(e.get('src', '')), str(e.get('dst', ''))
        etype = str(e.get('type', 'CALLS'))
        out.setdefault(src, []).append((dst, etype))
        out.setdefault(dst, [])
        inc.setdefault(dst, []).append((src, etype))
        inc.setdefault(src, [])
    return Graph(nodes=node_map, outgoing={k: tuple(v) for k, v in out.items()}, incoming={k: tuple(v) for k, v in inc.items()}, edges=tuple(edge_list))

def traverse_bfs(graph: Graph, seed_ids: Iterable[str], direction: str, max_hops: int, allowed_types: frozenset[str] = CALL_FLOW_EDGE_TYPES) -> tuple[set[str], dict[str, int]]:
    """Bounded BFS returning (reached non-seed entities, hop distance per entity).

    Seeds are pre-visited so they can never be reported as their own impact.
    A traversal that would exceed `max_hops` stops rather than continuing, which
    is what makes a topology tripwire bounded instead of exponential.
    """
    valid_seeds = [s for s in seed_ids if s in graph.nodes or s in graph.outgoing]
    if not valid_seeds or max_hops <= 0:
        return set(), {}
    visited = set(valid_seeds)
    hops: dict[str, int] = {}
    queue = deque((s, 0) for s in valid_seeds)
    adjacency = graph.incoming if direction == 'incoming' else graph.outgoing
    while queue:
        current, depth = queue.popleft()
        if depth >= max_hops:
            continue
        for neighbour, etype in adjacency.get(current, ()):
            if etype not in allowed_types:
                continue
            if neighbour not in visited:
                visited.add(neighbour)
                hops[neighbour] = depth + 1
                queue.append((neighbour, depth + 1))
    impact = visited - set(valid_seeds)
    return impact, {k: v for k, v in hops.items() if k in impact}

def compute_blast_radius(graph: Graph, changed_entities: Iterable[str], test_entities: Iterable[str] = (), max_hops: int = 2) -> BlastRadius:
    """Union of bounded inbound and outbound reachability from the changed set."""
    seeds = [str(s) for s in changed_entities]
    tests = {str(t) for t in test_entities}
    callers, caller_hops = traverse_bfs(graph, seeds, 'incoming', max_hops)
    callees, callee_hops = traverse_bfs(graph, seeds, 'outgoing', max_hops)
    reached = callers | callees
    coverage_gap = sorted(reached - tests) if tests else []
    risk = min(1.0, len(callers) * 0.1 + len(callees) * 0.05 + len(coverage_gap) * 0.2)
    packages: set[str] = set()
    impacted = reached | set(seeds)
    for e in graph.edges:
        if str(e.get('type', 'CALLS')) != 'DEPENDS_ON':
            continue
        src, dst = str(e.get('src', '')), str(e.get('dst', ''))
        if src in impacted or dst in impacted:
            pkg = (e.get('metadata') or {}).get('package')
            if pkg:
                packages.add(str(pkg))
    hops: dict[str, int] = {}
    for eid in reached:
        hops[eid] = min(caller_hops.get(eid, 999), callee_hops.get(eid, 999))
    return BlastRadius(affected_callers=tuple(sorted(callers)), affected_callees=tuple(sorted(callees)), impacted=tuple(sorted(impacted)), coverage_gap=tuple(coverage_gap), risk_score=round(risk, 4), dependency_packages=tuple(sorted(packages)), hop_distances=hops)

def deterministic_ranking(hop_distances: dict[str, int], k_values: Sequence[int] = (10, 25, 50)) -> dict[str, tuple[str, ...]]:
    """Orders entities by (hop distance asc, id asc) so ranking is reproducible."""
    ordered = sorted(hop_distances.keys(), key=lambda eid: (hop_distances[eid], eid))
    return {f'top_{k}': tuple(ordered[:k]) for k in k_values}
