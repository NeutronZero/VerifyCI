import sqlite3
from pathlib import Path

from verifyci.ingestion.dependency import VulnerabilityCache
from verifyci.interface.commands import resolve_db, resolve_repository
from verifyci.storage.graph_store import latest_revision_id


def run_vuln(db_path: str | None = None, cache_path: str = "./storage/vuln_cache.db",
             import_path: str | None = None) -> dict:
    """Offline vulnerability lookup. Findings enter the cache only via an
    explicit local import file ({package: [{id, ...}]}) — V1 never fetches
    over the network.

    A DB that cannot be read is an error, not an empty report: the old
    code returned `findings: []` on a wrong path, a locked DB, or a
    corrupt file, and a `len(findings) == 0` CI gate went green on a scan
    that never ran.
    """
    import json
    db = resolve_db(db_path)
    cache = VulnerabilityCache(Path(cache_path))
    imported = 0
    if import_path:
        with open(import_path, encoding="utf-8") as fh:
            data = json.load(fh)
        from verifyci.contracts.edge import Edge as _Edge, EdgeType as _ET
        edges = [_Edge(id=f"dep__{pkg}", revision_id="", src_entity_id="",
                       dst_entity_id=f"{pkg}", type=_ET.DEPENDS_ON,
                       metadata={"package": pkg}) for pkg in data]
        imported = cache.refresh(edges, findings=data)
    findings: list[dict] = []
    try:
        from verifyci.interface.commands import InfraError, open_for_read
        try:
            conn = open_for_read(db)
        except (InfraError, sqlite3.Error, OSError) as e:
            # Read-only open: a wrong path is an error, never a silently
            # created empty database (the old RW connect+scan did that).
            kind = getattr(e, "kind", f"cannot_open_db: {type(e).__name__}: {e}")
            return {"db_path": db, "status": "INFRA_ERROR", "packages_checked": 0,
                    "findings": [], "imported": imported, "error": str(kind)}
        try:
            # Latest revision only: unfiltered, every superseded row
            # re-scanned, and fixed versions kept flagging. DBs without
            # a revisions table (hand-built, tests) fall back to the
            # unfiltered scan rather than matching nothing.
            has_revisions = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"
                " AND name = 'revisions'").fetchone()[0]
            revision_id = latest_revision_id(conn, resolve_repository(db)) \
                if has_revisions else ""
            if revision_id:
                rows = conn.execute(
                    "SELECT metadata_json FROM edges WHERE type = 'DEPENDS_ON'"
                    " AND revision_id = ? LIMIT 5001",
                    (revision_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT metadata_json FROM edges WHERE type = 'DEPENDS_ON'"
                    " LIMIT 5001"
                ).fetchall()
        except sqlite3.Error as e:
            return {"db_path": db, "status": "INFRA_ERROR", "packages_checked": 0,
                    "findings": [], "imported": imported,
                    "error": f"query_failed: {type(e).__name__}: {e}"}
        finally:
            conn.close()
        # The 5001st row is a tripwire, not data: a silently
        # truncated scan gates green on packages it never examined.
        truncated = len(rows) > 5000
        for (meta_json,) in rows[:5000]:
            try:
                meta = json.loads(meta_json) if meta_json else {}
            except ValueError:
                continue
            edge = type("Edge", (), {"metadata": meta})()
            for vuln in cache.lookup(edge):
                findings.append({"package": meta.get("package"), **vuln})
    finally:
        cache.close()
    return {"db_path": db, "packages_checked": len(rows[:5000]), "findings": findings,
            "imported": imported, "truncated": truncated}
