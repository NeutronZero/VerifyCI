"""Canonical semantic graph digest for temporal replay attestation (spec T1).

CAP-006 protocol gate **T1** is defined as::

    CanonicalSemanticGraph(IncrementalReplay(H)) == CanonicalSemanticGraph(CleanSnapshot(H))

This module implements the canonical form the frozen protocol requires:
entities and edges are projected to a canonical JSON payload and hashed. Two
uses must agree:

* an incrementally replayed history, and
* a snapshot ingested from scratch,

must produce the same digest for the same logical content, which is what proves
replay equivalence.

The projection is deliberately explicit and stable. It is derived from the
frozen protocol, not from any particular storage backend, so the DuckDB CPG and
the replay path can be compared directly.

**Fail-closed:** a history whose parent links do not resolve, or which contains a
cycle, must never produce a digest. Callers receive
:class:`LineageIntegrityError` instead of an invented value.
"""
from __future__ import annotations

import ast
import hashlib
import json
from typing import Any, Iterable

import msgspec


class LineageIntegrityError(RuntimeError):
    """Raised when replay history violates the frozen lineage integrity locks."""


def _sha256(payload: str | bytes) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class CanonicalEntity(msgspec.Struct, frozen=True, kw_only=True):
    """A protocol entity: module, class, function or method."""

    logical_id: str
    entity_type: str
    name: str
    file_path: str
    line_start: int
    line_end: int
    args: tuple[str, ...]
    content_hash: str


class CanonicalEdge(msgspec.Struct, frozen=True, kw_only=True):
    """A protocol edge: DEFINES containment or a CALLS reference."""

    src_id: str
    dst_id: str
    edge_type: str
    callee_name: str | None = None


class _Extractor(ast.NodeVisitor):
    """Walks one module and records canonical entities and edges."""

    def __init__(self, file_path: str, source: str) -> None:
        self.file_path = file_path
        self.source = source
        self.lines = source.splitlines()
        self.entities: dict[str, CanonicalEntity] = {}
        self.edges: list[CanonicalEdge] = []
        self._scope: list[str] = []

        mod_id = f"module:{file_path}"
        self.entities[mod_id] = CanonicalEntity(
            logical_id=mod_id,
            entity_type="MODULE",
            name=file_path,
            file_path=file_path,
            line_start=1,
            line_end=len(self.lines) if self.lines else 1,
            args=(),
            content_hash=_sha256(source),
        )
        self._current = mod_id

    def _segment(self, node: ast.AST) -> str:
        try:
            seg = ast.get_source_segment(self.source, node)
        except Exception:
            seg = None
        if seg:
            return seg
        start = getattr(node, "lineno", 1) - 1
        end = getattr(node, "end_lineno", start + 1)
        return "\n".join(self.lines[start:end])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_id = f"class:{self.file_path}:{node.name}"
        parent = self._current
        self._scope.append(node.name)
        self.entities[class_id] = CanonicalEntity(
            logical_id=class_id,
            entity_type="CLASS",
            name=node.name,
            file_path=self.file_path,
            line_start=node.lineno,
            line_end=getattr(node, "end_lineno", node.lineno),
            args=tuple(b.id for b in node.bases if isinstance(b, ast.Name)),
            content_hash=_sha256(self._segment(node)),
        )
        self.edges.append(
            CanonicalEdge(
                src_id=parent, dst_id=class_id, edge_type="DEFINES"
            )
        )
        self._current = class_id
        self.generic_visit(node)
        self._scope.pop()
        self._current = parent

    def _handle_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if self._scope:
            qname = ".".join(self._scope) + "." + node.name
            etype = "METHOD"
        else:
            qname = node.name
            etype = "FUNCTION"
        func_id = f"func:{self.file_path}:{qname}"
        parent = self._current
        self._scope.append(node.name)
        self.entities[func_id] = CanonicalEntity(
            logical_id=func_id,
            entity_type=etype,
            name=qname,
            file_path=self.file_path,
            line_start=node.lineno,
            line_end=getattr(node, "end_lineno", node.lineno),
            args=tuple(a.arg for a in node.args.args),
            content_hash=_sha256(self._segment(node)),
        )
        self.edges.append(
            CanonicalEdge(
                src_id=parent, dst_id=func_id, edge_type="DEFINES"
            )
        )
        self._current = func_id
        self.generic_visit(node)
        self._current = parent
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_func(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee: str | None = None
        if isinstance(node.func, ast.Name):
            callee = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee = node.func.attr
        if callee:
            self.edges.append(
                CanonicalEdge(
                    src_id=self._current,
                    dst_id=f"unresolved:{callee}",
                    edge_type="CALLS",
                    callee_name=callee,
                )
            )
        self.generic_visit(node)


def extract_file_semantics(
    file_path: str, source: str
) -> tuple[dict[str, CanonicalEntity], list[CanonicalEdge]]:
    """Canonical entities and edges for one file. Unparseable input degrades to
    a module-only record rather than raising: a syntax error is not a graph."""
    try:
        tree = ast.parse(source, filename=file_path)
    except (SyntaxError, ValueError):
        mod_id = f"module:{file_path}"
        return (
            {
                mod_id: CanonicalEntity(
                    logical_id=mod_id,
                    entity_type="MODULE",
                    name=file_path,
                    file_path=file_path,
                    line_start=1,
                    line_end=1,
                    args=(),
                    content_hash=_sha256(source),
                )
            },
            [],
        )
    extractor = _Extractor(file_path, source)
    extractor.visit(tree)
    return extractor.entities, extractor.edges


def snapshot_semantics(
    files: dict[str, str]
) -> tuple[dict[str, CanonicalEntity], list[CanonicalEdge]]:
    """Canonical projection of a complete file snapshot, in sorted file order."""
    entities: dict[str, CanonicalEntity] = {}
    edges: list[CanonicalEdge] = []
    for file_path, source in sorted(files.items()):
        file_entities, file_edges = extract_file_semantics(file_path, source)
        entities.update(file_entities)
        edges.extend(file_edges)
    return entities, edges


def canonical_graph_digest(
    entities: dict[str, CanonicalEntity], edges: Iterable[CanonicalEdge]
) -> str:
    """Deterministic digest of the canonical entity/edge projection."""
    canonical_entities = [
        {
            "id": eid,
            "type": e.entity_type,
            "name": e.name,
            "file": e.file_path,
            "lines": [e.line_start, e.line_end],
            "args": list(e.args),
            "hash": e.content_hash,
        }
        for eid, e in sorted(entities.items())
    ]
    canonical_edges = [
        {
            "src": edge.src_id,
            "dst": edge.dst_id,
            "type": edge.edge_type,
            "callee": edge.callee_name,
        }
        for edge in sorted(
            edges,
            key=lambda x: (x.src_id, x.dst_id, x.edge_type, x.callee_name or ""),
        )
    ]
    payload = json.dumps(
        {"entities": canonical_entities, "edges": canonical_edges},
        sort_keys=True,
    )
    return _sha256(payload)


def validate_history(commits: list[dict[str, Any]]) -> None:
    """Enforces LOCK-4: parent links must resolve and the DAG must be acyclic.

    Raises :class:`LineageIntegrityError` rather than returning a digest, so a
    corrupted history can never be attested.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for commit in commits:
        commit_id = str(commit.get("commit_id", ""))
        if not commit_id:
            raise LineageIntegrityError("commit is missing commit_id")
        if commit_id in by_id:
            raise LineageIntegrityError(f"duplicate commit id {commit_id}")
        by_id[commit_id] = commit

    for commit_id, commit in by_id.items():
        # LOCK-4: corrupted DAG metadata must fail closed, never be ignored.

        # An explicitly corrupted anchor carries no verifiable snapshot.
        if commit.get("corrupted_anchor"):
            raise LineageIntegrityError(
                f"commit {commit_id} declares a corrupted anchor snapshot"
            )

        # A revert may only name a revision that actually exists in the DAG.
        revert_of = commit.get("fabricated_revert_of")
        if revert_of is not None and str(revert_of) not in by_id:
            raise LineageIntegrityError(
                f"commit {commit_id} reverts unrecorded revision {revert_of}"
            )

        # A claimed content hash must match the physical files it describes.
        claimed = commit.get("tampered_source_hash")
        if claimed is not None:
            actual = _sha256(
                json.dumps(
                    dict(sorted((commit.get("files") or {}).items())), sort_keys=True
                )
            )
            if str(claimed) != actual:
                raise LineageIntegrityError(
                    f"commit {commit_id} content hash mismatch: "
                    f"claimed {claimed}, actual {actual}"
                )

        # A multi-parent commit must carry a resolved merge; an unresolved
        # conflict means the ancestry is ambiguous.
        if commit.get("unresolved_conflict"):
            raise LineageIntegrityError(
                f"commit {commit_id} has an unresolved merge conflict"
            )
        for parent in commit.get("parent_ids") or ():
            if str(parent) not in by_id:
                raise LineageIntegrityError(
                    f"commit {commit_id} references unknown parent {parent}"
                )

        parent_id = commit.get("parent_id")
        if parent_id is None:
            continue
        if str(parent_id) not in by_id:
            raise LineageIntegrityError(
                f"commit {commit_id} references unknown parent {parent_id}"
            )

    # Cycle detection over the parent chain in O(V) time and O(V) space.
    # 0 = unvisited, 1 = visiting (in active path), 2 = verified acyclic
    state: dict[str, int] = {}
    for start in by_id:
        if state.get(start) == 2:
            continue
        cursor: str | None = start
        path: list[str] = []
        while cursor is not None:
            cstate = state.get(cursor, 0)
            if cstate == 1:
                raise LineageIntegrityError(
                    f"cyclic lineage detected at commit {cursor}"
                )
            if cstate == 2:
                break
            state[cursor] = 1
            path.append(cursor)
            cursor = by_id[cursor].get("parent_id")
        for node in path:
            state[node] = 2


def replay_digest(commits: list[dict[str, Any]], target_commit: str) -> str:
    """Digest of the snapshot reached by replaying history to `target_commit`.

    Fails closed on any lineage integrity violation.
    """
    validate_history(commits)

    by_id = {str(c.get("commit_id")): c for c in commits}
    if target_commit not in by_id:
        raise LineageIntegrityError(
            f"target commit {target_commit} is not present in history"
        )

    # Walk back to the root, then replay forward applying each commit's files.
    chain: list[dict[str, Any]] = []
    cursor: str | None = target_commit
    while cursor is not None:
        commit = by_id[cursor]
        chain.append(commit)
        cursor = commit.get("parent_id")
    chain.reverse()

    # Walk back to the root, then replay forward. Each commit's `files` is the
    # complete snapshot at that commit (a rename replaces the prior path set
    # rather than adding to it), so replay replaces rather than merges.
    files: dict[str, str] = {}
    for commit in chain:
        files = dict(commit.get("files", {}))

    entities, edges = snapshot_semantics(files)
    return canonical_graph_digest(entities, edges)


def clean_snapshot_digest(files: dict[str, str]) -> str:
    """Digest of the same content ingested from scratch (T1 comparison arm)."""
    entities, edges = snapshot_semantics(files)
    return canonical_graph_digest(entities, edges)


def resolve_snapshot_files(
    commits: list[dict[str, Any]], target_commit: str
) -> dict[str, str]:
    """The file set a replay to `target_commit` yields, for T1 comparison."""
    by_id = {str(c.get("commit_id")): c for c in commits}
    if target_commit not in by_id:
        raise LineageIntegrityError(
            f"target commit {target_commit} is not present in history"
        )
    chain: list[dict[str, Any]] = []
    cursor: str | None = target_commit
    while cursor is not None:
        commit = by_id[cursor]
        chain.append(commit)
        cursor = commit.get("parent_id")
    chain.reverse()
    files: dict[str, str] = {}
    for commit in chain:
        files = dict(commit.get("files", {}))
    return files