"""Entity extraction, source caching, and changed-scope mapping for Python and TS/JS."""

from __future__ import annotations

import ast
from dataclasses import asdict
from typing import Any, Mapping, Sequence

from verifyci.contracts.model import DiffEntry, Entity
from verifyci.contracts.names import normalize_repo_path
from verifyci.runtime.budget import DEFAULT_BUDGET, WorkBudget
from verifyci.scope.models import (
    CallSite,
    ChangedScope,
    ImportFact,
    Param,
    SourceFacts,
    git_blob_id,
)
from verifyci.scope.parsers import (
    SUPPORTED_CODE_EXTENSIONS,
    TEXT_SUFFIXES,
    TS_JS_EXTENSIONS,
    frontend_identity,
    path_suffix,
)
from verifyci.scope.python_scope import analyze_python, is_safe_module_construct
from verifyci.scope.ts_scope import analyze_typescript


def _analyze_source_uncached(
    path: str,
    source: str,
    source_roots: Sequence[str] = (),
    blob_hash: str = "",
    budget: WorkBudget = DEFAULT_BUDGET,
) -> SourceFacts:
    encoded = source.encode("utf-8")
    if len(encoded) > budget.max_file_bytes:
        return SourceFacts(
            path=path,
            language=path_suffix(path) or "unknown",
            supported=False,
            parse_error=f"parse_resource_limit: file size {len(encoded)} exceeds max_file_bytes {budget.max_file_bytes}",
        )
    suffix = path_suffix(path)
    if suffix == "py":
        return analyze_python(
            path, source, source_roots, blob_hash=blob_hash, budget=budget
        )
    if suffix in TS_JS_EXTENSIONS:
        return analyze_typescript(
            path, source, blob_hash=blob_hash, budget=budget
        )
    if suffix in TEXT_SUFFIXES or ("/" not in path and "." not in path):
        return SourceFacts(path=path, language="text", supported=True)
    return SourceFacts(
        path=path,
        language=suffix or "unknown",
        supported=False,
        parse_error="unsupported language frontend",
    )


def _facts_to_cache(facts: SourceFacts) -> dict[str, Any]:
    return {
        "path": facts.path,
        "language": facts.language,
        "supported": facts.supported,
        "entities": [asdict(entity) for entity in facts.entities],
        "calls": [asdict(call) for call in facts.calls],
        "imports": [asdict(item) for item in facts.imports],
        "name_loads": sorted(facts.name_loads),
        "exports": sorted(facts.exports),
        "parse_error": facts.parse_error,
        "has_dynamic_dispatch": facts.has_dynamic_dispatch,
        "has_unknown_decorator": facts.has_unknown_decorator,
    }


def _facts_from_cache(value: Mapping[str, Any]) -> SourceFacts:
    entities = []
    for raw in value["entities"]:
        item = dict(raw)
        item["parameters"] = tuple(tuple(param) for param in item.get("parameters", ()))
        entities.append(Entity(**item))
    calls = [
        CallSite(**{**dict(raw), "keywords": tuple(raw.get("keywords", ()))})  # ty: ignore[invalid-argument-type]
        for raw in value["calls"]
    ]
    imports = [
        ImportFact(
            **{  # ty: ignore[invalid-argument-type]
                **dict(raw),
                "names": tuple(raw.get("names", ())),
                "aliases": tuple(tuple(pair) for pair in raw.get("aliases", ())),
            }
        )
        for raw in value["imports"]
    ]
    return SourceFacts(
        path=str(value["path"]),
        language=str(value["language"]),
        supported=bool(value["supported"]),
        entities=tuple(entities),
        calls=tuple(calls),
        imports=tuple(imports),
        name_loads=frozenset(value["name_loads"]),
        exports=frozenset(value["exports"]),
        parse_error=str(value["parse_error"]),
        has_dynamic_dispatch=bool(value["has_dynamic_dispatch"]),
        has_unknown_decorator=bool(value["has_unknown_decorator"]),
    )


def analyze_source(
    path: str,
    source: str,
    source_roots: Sequence[str] = (),
    *,
    fact_provider=None,
    toolchain_fingerprint: str = "",
    blob_hash: str = "",
    budget: WorkBudget = DEFAULT_BUDGET,
) -> SourceFacts:
    if fact_provider is None or not toolchain_fingerprint or not blob_hash:
        return _analyze_source_uncached(
            path, source, source_roots, blob_hash=blob_hash, budget=budget
        )
    from verifyci.index.provider import FactProvider

    language_id, frontend_version = frontend_identity(path)
    components = FactProvider.tier1_components(
        toolchain_fingerprint=toolchain_fingerprint,
        blob_hash=blob_hash,
        path=normalize_repo_path(path),
        language_id=language_id,
        frontend_version=frontend_version,
        source_roots=tuple(source_roots),
    )
    cached = fact_provider.get_or_compute(
        "symbol_facts",
        components,
        lambda: _facts_to_cache(
            _analyze_source_uncached(
                path, source, source_roots, blob_hash=blob_hash, budget=budget
            )
        ),
    )
    try:
        return _facts_from_cache(cached)
    except (KeyError, TypeError, ValueError):
        # A malformed local entry is not evidence. Rebuild from the pinned blob.
        facts = _analyze_source_uncached(
            path, source, source_roots, blob_hash=blob_hash, budget=budget
        )
        fact_provider.cache_store.put("symbol_facts", components, _facts_to_cache(facts))
        return facts


def find_matching_entity_detailed(
    entities: Sequence[Entity], start_line: int, count: int
) -> tuple[Entity | None, bool]:
    """Find the matching entity and report whether boundary conflict occurred."""
    if count <= 0:
        return None, False
    end_line = start_line + count - 1
    overlapping = [
        e for e in entities
        if not (end_line < e.start_line or start_line > e.end_line)
    ]
    if not overlapping:
        return None, False
    overlapping.sort(key=lambda e: (e.end_line - e.start_line), reverse=True)
    for i in range(len(overlapping) - 1):
        outer = overlapping[i]
        inner = overlapping[i + 1]
        if not (outer.start_line <= inner.start_line and inner.end_line <= outer.end_line):
            return None, True
    return overlapping[-1], False


def find_matching_entity(entities: Sequence[Entity], start_line: int, count: int) -> Entity | None:
    """Find the unique entity that contains or uniquely maps to the line range."""
    effective_count = 1 if count == 0 and start_line > 0 else count
    match, _ = find_matching_entity_detailed(entities, start_line, effective_count)
    return match


def extract_entities(source: bytes | str, path: str, source_roots: Sequence[str] = ()) -> tuple[Entity, ...]:
    src_str = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
    facts = analyze_source(path, src_str, source_roots)
    return facts.entities


def _mapped_hunk(path: str, hunk: Any, mapped_entity: str | None) -> dict[str, Any]:
    return {
        "file": path,
        "old_start": hunk.old_start,
        "old_count": hunk.old_count,
        "new_start": hunk.new_start,
        "new_count": hunk.new_count,
        "mapped_entity": mapped_entity,
    }


def _get_cached_tree(
    cache: dict[str, ast.Module | None], side: str, source_text: str
) -> ast.Module | None:
    if side not in cache:
        tree: ast.Module | None = None
        if source_text:
            try:
                tree = ast.parse(source_text)
            except SyntaxError:
                tree = None
        cache[side] = tree
    return cache[side]


def build_changed_scope(
    entries: Sequence[DiffEntry],
    *,
    source_roots: Sequence[str] = (),
    rename_limit_exceeded: bool = False,
    fact_provider=None,
    toolchain_fingerprint: str = "",
    object_format: str = "",
    budget: WorkBudget = DEFAULT_BUDGET,
) -> ChangedScope:
    base_facts: dict[str, SourceFacts] = {}
    head_facts: dict[str, SourceFacts] = {}
    changed: set[str] = set()
    base_entities: set[str] = set()
    head_entities: set[str] = set()
    unmapped: list[dict[str, Any]] = []
    mapped_hunks: list[dict[str, Any]] = []
    entity_changes: dict[str, dict[str, Any]] = {}
    renames: list[dict[str, Any]] = []

    def _record_unmapped(path: str, hunk: Any, reason_code: str) -> None:
        unmapped.append({"path": path, "hunk": hunk.to_dict(), "reason_code": reason_code})
        mapped_hunks.append(_mapped_hunk(path, hunk, None))

    for entry in entries:
        if entry.base_path and not entry.is_binary and not entry.is_submodule:
            bf = analyze_source(
                entry.base_path,
                entry.base_source,
                source_roots,
                fact_provider=fact_provider,
                toolchain_fingerprint=toolchain_fingerprint,
                blob_hash=f"{object_format}:{entry.base_blob}" if object_format and entry.base_blob else "",
                budget=budget,
            )
            base_facts[entry.base_path] = bf
            base_entities.update(e.qname for e in bf.entities)
        if entry.head_path and not entry.is_binary and not entry.is_submodule:
            hf = analyze_source(
                entry.head_path,
                entry.head_source,
                source_roots,
                fact_provider=fact_provider,
                toolchain_fingerprint=toolchain_fingerprint,
                blob_hash=f"{object_format}:{entry.head_blob}" if object_format and entry.head_blob else "",
                budget=budget,
            )
            head_facts[entry.head_path] = hf
            head_entities.update(e.qname for e in hf.entities)

        if entry.is_binary or entry.is_submodule:
            continue

        if entry.is_renamed and not entry.hunks:
            renames.append(
                {
                    "base_path": entry.base_path,
                    "head_path": entry.head_path,
                    "base_blob": entry.base_blob,
                    "head_blob": entry.head_blob,
                    "base_mode": entry.base_mode,
                    "head_mode": entry.head_mode,
                    "mapping": "file_rename_content_identical",
                }
            )
            bf_rename = base_facts.get(entry.base_path)
            hf_rename = head_facts.get(entry.head_path)
            if bf_rename:
                changed.update(e.qname for e in bf_rename.entities)
            if hf_rename:
                changed.update(e.qname for e in hf_rename.entities)
            continue

        if not entry.hunks:
            continue

        path = entry.head_path or entry.base_path
        bf = base_facts.get(entry.base_path)
        hf = head_facts.get(entry.head_path)

        parse_err = (bf and bf.parse_error) or (hf and hf.parse_error)
        if parse_err and not str(parse_err).startswith("unsupported language"):
            reason_code = (
                "parse_resource_limit"
                if str(parse_err).startswith("parse_resource_limit")
                else "parse_error"
            )
            for hunk in entry.hunks:
                _record_unmapped(path, hunk, reason_code)
            continue

        if (bf and not bf.supported) or (hf and not hf.supported):
            for hunk in entry.hunks:
                _record_unmapped(path, hunk, "unsupported_language")
            continue

        sfx = path_suffix(path)
        if sfx not in SUPPORTED_CODE_EXTENSIONS:
            for hunk in entry.hunks:
                mapped_hunks.append(_mapped_hunk(path, hunk, path))
            continue

        b_ents = bf.entities if bf else ()
        h_ents = hf.entities if hf else ()
        b_by_qname = {e.qname: e for e in b_ents}
        h_by_qname = {e.qname: e for e in h_ents}

        parsed_trees: dict[str, ast.Module | None] = {}

        for hunk in entry.hunks:
            m_base, base_conflict = find_matching_entity_detailed(b_ents, hunk.old_start, hunk.old_count)
            m_head, head_conflict = find_matching_entity_detailed(h_ents, hunk.new_start, hunk.new_count)

            if base_conflict or head_conflict:
                _record_unmapped(path, hunk, "mapping_unresolved")
                continue

            if m_base is not None and m_head is not None and m_base.qname == m_head.qname:
                qname = m_head.qname
                changed.add(qname)
                entity_changes[qname] = {"change": "modified", "base_e": m_base, "head_e": m_head}
                mapped_hunks.append(_mapped_hunk(path, hunk, qname))
            elif m_base is None and m_head is not None:
                qname = m_head.qname
                changed.add(qname)
                if qname in b_by_qname:
                    entity_changes[qname] = {"change": "modified", "base_e": b_by_qname[qname], "head_e": m_head}
                else:
                    entity_changes[qname] = {"change": "added", "base_e": None, "head_e": m_head}
                mapped_hunks.append(_mapped_hunk(path, hunk, qname))
            elif m_base is not None and m_head is None:
                head_e = h_by_qname.get(m_base.qname) if hunk.new_count == 0 else None
                if head_e is not None:
                    qname = head_e.qname
                    changed.add(qname)
                    entity_changes[qname] = {"change": "modified", "base_e": m_base, "head_e": head_e}
                else:
                    qname = m_base.qname
                    changed.add(qname)
                    entity_changes[qname] = {"change": "removed", "base_e": m_base, "head_e": None}
                mapped_hunks.append(_mapped_hunk(path, hunk, qname))
            elif m_base is None and m_head is None:
                if (
                    sfx == "py"
                    and is_safe_module_construct(
                        entry.base_source,
                        hunk.old_start,
                        hunk.old_count,
                        entry.head_source,
                        hunk.new_start,
                        hunk.new_count,
                        base_tree=_get_cached_tree(parsed_trees, "base", entry.base_source),
                        head_tree=_get_cached_tree(parsed_trees, "head", entry.head_source),
                    )
                ):
                    mapped_hunks.append(_mapped_hunk(path, hunk, "other_text"))
                else:
                    _record_unmapped(path, hunk, "mapping_unresolved")
            else:
                _record_unmapped(path, hunk, "mapping_unresolved")

    entities_out = []
    for qname, info in sorted(entity_changes.items()):
        be = info["base_e"]
        he = info["head_e"]
        ent_ref = he or be
        item = {
            "base_blob": be.blob_id if be else None,
            "base_span": be.span if be else None,
            "change": info["change"],
            "head_blob": he.blob_id if he else None,
            "head_span": he.span if he else None,
            "kind": ent_ref.kind,
            "qname": qname,
        }
        if ent_ref.is_async:
            item["is_async"] = True
        if ent_ref.is_export and not ent_ref.file_path.endswith(".py"):
            item["is_export"] = True
        entities_out.append(item)

    return ChangedScope(
        base_facts=base_facts,
        head_facts=head_facts,
        changed_entities=frozenset(changed),
        base_entities=frozenset(base_entities),
        head_entities=frozenset(head_entities),
        unmapped_hunks=tuple(unmapped),
        rename_limit_exceeded=rename_limit_exceeded,
        mapped_hunks=tuple(mapped_hunks),
        mapped_entities=tuple(entities_out),
        renames=tuple(renames),
    )


__all__ = [
    "CallSite",
    "ChangedScope",
    "ImportFact",
    "Param",
    "SourceFacts",
    "analyze_python",
    "analyze_source",
    "analyze_typescript",
    "build_changed_scope",
    "extract_entities",
    "find_matching_entity",
    "find_matching_entity_detailed",
    "git_blob_id",
    "is_safe_module_construct",
]
