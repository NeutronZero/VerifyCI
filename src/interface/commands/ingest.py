from pathlib import Path

from src.ingestion.language import INGESTIBLE_EXTENSIONS, detect_language
from src.ingestion.parser import TreeSitterParser, compute_source_hash
from src.ingestion.extractor import extract_entities, extract_edges
from src.ingestion.dependency import extract_dependencies
from src.storage.graph_store import GraphStore
from src.storage.metadata import MetadataStore
from src.storage.revision import create_revision

MANIFESTS = ("package.json", "requirements.txt", "Cargo.toml", "pom.xml", "go.mod")


SKIP_DIRS = frozenset({
    ".verifyci", ".git", ".hg", ".svn", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".eggs", ".venv", "venv",
    "env", "node_modules", "dist", "build", "target", ".idea", ".vscode",
})


def _collect(repo: Path) -> tuple[list[tuple[str, str, bytes]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Pass 1 (no parsing): gather source files + dependency manifests.

    Returns ((rel_path, language, bytes) list, manifest (rel_path, sha256) list).
    """
    sources: list[tuple[str, str, bytes]] = []
    texts: list[tuple[str, str]] = []
    for file in sorted(repo.rglob("*")):
        if not file.is_file():
            continue
        # Relative parts only: matching absolute parts skipped every file
        # of repos living under /build/, /env/, or */target/* with no
        # warning. (A top-level source package literally named `build`
        # or `dist` is still skipped — documented SKIP_DIRS behavior.)
        try:
            rel_parts = file.relative_to(repo).parts[:-1]
        except ValueError:
            continue
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if file.name in MANIFESTS:
            # Manifests first: requirements.txt also matches the .txt
            # ingestible suffix, which used to swallow it silently and
            # drop Python dependencies from the graph.
            texts.append((str(file.relative_to(repo)), file.read_text(errors="replace")))
        elif file.suffix.lower() in INGESTIBLE_EXTENSIONS:
            language = detect_language(str(file))
            # Docs have no AST: parsed with tree=None yields a MODULE entity.
            sources.append((str(file.relative_to(repo)), language, file.read_bytes()))
    manifest = [(rel, compute_source_hash(src)) for rel, _, src in sources]
    manifest += [(rel, compute_source_hash(text.encode("utf-8"))) for rel, text in texts]
    return sources, texts, manifest


def _meta_rev(meta, repo, rel):
    record = meta.get_file(str(repo / rel))
    return record[4] if record else ""


def _carry_forward(store, carried_sources, carried_texts, revision_id, now) -> tuple[int, int]:
    """Copy unchanged files' entities/edges into a new revision (re-keyed),
    so incremental revisions stay complete. Returns (entities, edges)."""
    import dataclasses
    from src.contracts.identity import compute_revision_entity_id

    n_e = n_d = 0
    id_map: dict[str, str] = {}
    old_edges = []
    by_rev: dict[str, list[str]] = {}
    for rel, old_rev in carried_sources:
        if old_rev:
            by_rev.setdefault(old_rev, []).append(rel)
    for old_rev, rels in by_rev.items():
        wanted = set(rels)
        for e in store.get_entities_by_revision(old_rev):
            if e.file_path not in wanted:
                continue
            new_id = compute_revision_entity_id(e.logical_entity_id, revision_id)
            id_map[e.revision_entity_id] = new_id
            store.insert_entity(dataclasses.replace(
                e, revision_entity_id=new_id, revision_id=revision_id,
                valid_from=now, valid_until=None, t_created=now, t_expired=None))
            n_e += 1
        old_edges.extend(store.get_edges_by_revision(old_rev))
    text_revs = {old_rev for _, old_rev in carried_texts if old_rev}
    for old_rev in text_revs:
        if old_rev not in by_rev:
            old_edges.extend(store.get_edges_by_revision(old_rev))
    seen = set()
    new_edges = []
    for e in old_edges:
        if e.src_entity_id in id_map and e.dst_entity_id in id_map:
            src, dst = id_map[e.src_entity_id], id_map[e.dst_entity_id]
        elif e.type.value == "DEPENDS_ON":
            src, dst = e.src_entity_id, e.dst_entity_id
        elif e.type.value in ("CALLS_UNRESOLVED", "INHERITS_UNRESOLVED") \
                and e.src_entity_id in id_map:
            # Unresolved references carry by source: the dst is a name,
            # not an endpoint, so there is nothing on the far side to
            # re-key. Dropping them here silently weakened every
            # incremental graph's cross-file visibility.
            src, dst = id_map[e.src_entity_id], e.dst_entity_id
        else:
            continue  # cross-file edge with a changed endpoint: fresh extraction covers it
        etype = e.type.value
        subtype = e.subtype.value if e.subtype else ""
        extra = ""
        if etype in ("CALLS_UNRESOLVED", "INHERITS_UNRESOLVED"):
            # Parallel unresolved refs from one caller share src+dst("");
            # without the referenced name in the id, the seen-dedupe
            # below keeps only the first and drops the rest.
            meta = e.metadata or {}
            extra = "_" + (meta.get("callee") or meta.get("base") or "")
        eid = f"edge_{revision_id[:12]}_{src}_{dst}_{etype}_{subtype}{extra}"
        if eid in seen:
            continue
        seen.add(eid)
        new_edges.append(dataclasses.replace(
            e, id=eid, revision_id=revision_id, src_entity_id=src, dst_entity_id=dst,
            valid_from=now, valid_until=None, observed_at=now,
            t_created=now, t_expired=None))
    for e in new_edges:
        store.insert_edge(e)
        n_d += 1
    if id_map:
        carried_ids = set(id_map.values())
        store.close_superseded_entities(
            [e.logical_entity_id for e in store.get_entities_by_revision(revision_id)
             if e.revision_entity_id in carried_ids],
            revision_id, now)
    if new_edges:
        store.close_superseded_edges(new_edges, revision_id, now)
    return n_e, n_d


def run_ingest(path: str, incremental: bool = False,
               commit_id: str | None = None) -> dict:
    repo = Path(path)
    db_path = str(repo / ".verifyci" / "verifyci.db")
    store = GraphStore(db_path)
    meta = MetadataStore(db_path, conn=store.conn)
    try:
      with store.batch():
        return _run_ingest_inner(repo, db_path, store, meta, incremental, commit_id)
    finally:
        store.close()


def _run_ingest_inner(repo, db_path: str, store, meta, incremental: bool = False,
                      commit_id: str | None = None) -> dict:
        sources, texts, manifest = _collect(repo)
        collected = len(sources) + len(texts)

        if incremental:
            changed_paths = {
                rel for rel, digest in manifest
                if not (
                    (record := meta.get_file(str(repo / rel)))
                    and record[1] == digest
                )
            }
            carried_sources = [(s[0], _meta_rev(meta, repo, s[0])) for s in sources
                               if s[0] not in changed_paths]
            carried_texts = [(t[0], _meta_rev(meta, repo, t[0])) for t in texts
                             if t[0] not in changed_paths]
            sources = [s for s in sources if s[0] in changed_paths]
            texts = [t for t in texts if t[0] in changed_paths]
        else:
            carried_sources, carried_texts = [], []
        # Revision identity always covers the full manifest so equal repo
        # states yield equal revisions regardless of incremental mode.

        revision = create_revision(repository_id=repo.name, files=manifest,
                                     commit_id=commit_id)
        latest = store.get_latest_revision(repo.name)
        if latest is not None and latest.revision_id != revision.revision_id:
            import dataclasses
            revision = dataclasses.replace(revision, parent_revision_id=latest.revision_id)
        store.insert_revision(revision)
        snapshot = {"files": [{"path": p, "source_hash": h} for p, h in sorted(manifest)]}
        store.insert_anchor(revision.revision_id, snapshot)
        if revision.parent_revision_id:
            prev = store.get_anchor(revision.parent_revision_id) or {"files": []}
            prev_map = {f["path"]: f["source_hash"] for f in prev.get("files", [])}
            cur_map = dict(manifest)
            store.insert_delta(revision.parent_revision_id, revision.revision_id, {
                "added": sorted([p for p in cur_map if p not in prev_map]),
                "removed": sorted([p for p in prev_map if p not in cur_map]),
                "changed": sorted([p for p in cur_map
                                   if p in prev_map and prev_map[p] != cur_map[p]]),
            })
        parser = TreeSitterParser()
        totals = {"entities": 0, "edges": 0, "files": 0,
                  "skipped": collected - len(sources) - len(texts),
                  "closed_entities": 0, "closed_edges": 0,
                  "parse_errors": [],
                  "revision_id": revision.revision_id,
                  "parent_revision_id": revision.parent_revision_id,
                  "db_path": db_path}
        import time as _time
        closed_at = _time.time()
        for rel, language, source in sources:
            digest = compute_source_hash(source)
            try:
                parsed = parser.parse(rel, source, language)
            except ValueError:
                from src.ingestion.parser import ParsedFile
                parsed = ParsedFile(file_path=rel, source=source, source_hash=digest,
                                    language=language, tree=None)
            if parsed.tree is not None and getattr(
                    parsed.tree.root_node, "has_error", False):
                # A file that parses with ERROR nodes yields a partial,
                # possibly misleading graph. Record it; the MODULE-only
                # fallback still grounds the file.
                totals["parse_errors"].append(rel)
            entities = extract_entities(parsed, repo.name, revision.revision_id)
            edges = extract_edges(parsed, entities, revision.revision_id)
            for e in entities:
                store.insert_entity(e)
            for edge in edges:
                store.insert_edge(edge)
            totals["closed_entities"] += store.close_superseded_entities(
                [e.logical_entity_id for e in entities], revision.revision_id, closed_at)
            totals["closed_edges"] += store.close_superseded_edges(
                edges, revision.revision_id, closed_at)
            gone_e, gone_d = store.close_deleted_file_version(
                rel, [e.logical_entity_id for e in entities],
                revision.revision_id, closed_at)
            totals["closed_entities"] += gone_e
            totals["closed_edges"] += gone_d
            meta.upsert_file(str(repo / rel), digest, language, revision.revision_id)
            totals["entities"] += len(entities)
            totals["edges"] += len(edges)
            totals["files"] += 1
        for rel, text in texts:
            edges = extract_dependencies(rel, text, revision.revision_id)
            for edge in edges:
                store.insert_edge(edge)
            totals["closed_edges"] += store.close_superseded_edges(
                edges, revision.revision_id, closed_at)
            totals["edges"] += len(edges)
        if incremental and revision.parent_revision_id:
            carried_e, carried_d = _carry_forward(
                store, carried_sources, carried_texts, revision.revision_id, closed_at)
            totals["entities"] += carried_e
            totals["edges"] += carried_d
            totals["carried_entities"] = carried_e
            totals["carried_edges"] = carried_d
        # Disappearance closure runs last, against the complete new
        # revision (fresh rows plus carried ones): entities and edges
        # the new tree no longer contains are expired, so name lookups
        # and graph loads stop returning deleted code.
        gone_e, gone_d = store.close_disappeared(
            revision.revision_id, revision.parent_revision_id or "",
            repo.name, closed_at)
        totals["closed_entities"] += gone_e
        totals["closed_edges"] += gone_d
        totals["disappeared_entities"] = gone_e
        totals["disappeared_edges"] = gone_d
        return totals
