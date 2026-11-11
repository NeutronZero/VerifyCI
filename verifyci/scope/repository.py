"""Repository-wide symbol fact augmentation for reference and caller discovery."""

from __future__ import annotations

from typing import Sequence

from verifyci.contracts.manifest import CODE_EXTENSIONS
from verifyci.contracts.model import Entity
from verifyci.index.provider import FactProvider
from verifyci.runtime.budget import DEFAULT_BUDGET, WorkBudget
from verifyci.runtime.scheduler import run_deterministic_batch
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import analyze_source
from verifyci.scope.models import ChangedScope, SourceFacts
from verifyci.scope.parsers import path_suffix


def augment_scope_with_repository(
    scope: ChangedScope,
    *,
    git: GitRepo,
    base_rev: str,
    head_rev: str,
    source_roots: Sequence[str],
    fact_provider: FactProvider | None = None,
    toolchain_fingerprint: str = "",
    object_format: str = "",
    budget: WorkBudget = DEFAULT_BUDGET,
    jobs: int = 1,
) -> ChangedScope:
    """Add repository-local facts for reference and caller discovery.

    The changed-scope map is intentionally small. Deletion and contract checks
    also need live references and callers in unchanged files, so the gate
    materializes facts for repository code files at both endpoints.
    """
    base_facts = dict(scope.base_facts)
    head_facts = dict(scope.head_facts)
    base_blobs: dict[str, str] = {}
    base_tree_entries: list[tuple[str, str, str, str]] = []
    for mode, obj_type, object_id, path in git.list_tree(base_rev):
        if mode in ("160000", "120000") or obj_type != "blob":
            continue
        if path_suffix(path) not in CODE_EXTENSIONS:
            continue
        base_blobs[path] = object_id
        base_tree_entries.append((mode, obj_type, object_id, path))

    head_tree_entries: list[tuple[str, str, str, str]] = []
    for mode, obj_type, object_id, path in git.list_tree(head_rev):
        if mode in ("160000", "120000") or obj_type != "blob":
            continue
        if path_suffix(path) not in CODE_EXTENSIONS or path in head_facts:
            continue
        head_tree_entries.append((mode, obj_type, object_id, path))

    needed_blobs: list[str] = []
    for _, _, object_id, path in base_tree_entries:
        if path not in base_facts:
            needed_blobs.append(object_id)
    for _, _, object_id, path in head_tree_entries:
        if base_blobs.get(path) != object_id or path not in base_facts:
            needed_blobs.append(object_id)

    fetched_blobs = git.read_blobs(needed_blobs) if needed_blobs else {}

    def _parse_entry(item: tuple[str, str]) -> tuple[str, SourceFacts | None]:
        object_id, path = item
        raw = fetched_blobs.get(object_id)
        if raw is None:
            raw = git.read_blob(object_id)
        if b"\0" in raw:
            return path, None
        facts = analyze_source(
            path,
            raw.decode("utf-8", "replace"),
            source_roots,
            fact_provider=fact_provider,
            toolchain_fingerprint=toolchain_fingerprint,
            blob_hash=f"{object_format}:{object_id}" if object_format else object_id,
            budget=budget,
        )
        return path, facts

    base_to_parse = [
        (object_id, path)
        for _, _, object_id, path in base_tree_entries
        if path not in base_facts
    ]
    for path, facts in run_deterministic_batch(base_to_parse, _parse_entry, max_workers=jobs):
        if facts is not None:
            base_facts[path] = facts

    head_to_parse = []
    for _, _, object_id, path in head_tree_entries:
        if base_blobs.get(path) == object_id and path in base_facts:
            head_facts[path] = base_facts[path]
        elif path not in head_facts:
            head_to_parse.append((object_id, path))
    for path, facts in run_deterministic_batch(head_to_parse, _parse_entry, max_workers=jobs):
        if facts is not None:
            head_facts[path] = facts

    base_entities_set: set[str] = set()
    head_entities_set: set[str] = set()
    idx: dict[str, Entity] = {}
    for facts in base_facts.values():
        for e in facts.entities:
            base_entities_set.add(e.qname)
            idx[e.qname] = e
    for facts in head_facts.values():
        for e in facts.entities:
            head_entities_set.add(e.qname)
            idx[e.qname] = e

    return ChangedScope(
        base_facts=base_facts,
        head_facts=head_facts,
        changed_entities=scope.changed_entities,
        base_entities=frozenset(base_entities_set),
        head_entities=frozenset(head_entities_set),
        unmapped_hunks=scope.unmapped_hunks,
        rename_limit_exceeded=scope.rename_limit_exceeded,
        mapped_hunks=scope.mapped_hunks,
        mapped_entities=scope.mapped_entities,
        renames=scope.renames,
        _entity_index=idx,
    )


__all__ = ["augment_scope_with_repository"]
