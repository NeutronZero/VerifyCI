import sqlite3
from pathlib import Path

from src.ingestion.dependency import VulnerabilityCache
from src.interface.commands import resolve_db


def run_vuln(db_path: str | None = None, cache_path: str = "./storage/vuln_cache.db",
             import_path: str | None = None) -> dict:
    """Offline vulnerability lookup. Findings enter the cache only via an
    explicit local import file ({package: [{id, ...}]}) — V1 never fetches
    over the network."""
    import json
    db = resolve_db(db_path)
    cache = VulnerabilityCache(Path(cache_path))
    imported = 0
    if import_path:
        with open(import_path, encoding="utf-8") as fh:
            data = json.load(fh)
        from src.contracts.edge import Edge as _Edge, EdgeType as _ET
        edges = [_Edge(id=f"dep__{pkg}", revision_id="", src_entity_id="",
                       dst_entity_id=f"{pkg}", type=_ET.DEPENDS_ON,
                       metadata={"package": pkg}) for pkg in data]
        imported = cache.refresh(edges, findings=data)
    findings: list[dict] = []
    try:
        conn = sqlite3.connect(db)
        try:
            rows = conn.execute(
                "SELECT metadata_json FROM edges WHERE type = 'DEPENDS_ON' LIMIT 5000"
            ).fetchall()
        finally:
            conn.close()
    except (sqlite3.OperationalError, OSError):
        rows = []
    import json
    for (meta_json,) in rows:
        try:
            meta = json.loads(meta_json) if meta_json else {}
        except ValueError:
            continue
        edge = type("Edge", (), {"metadata": meta})()
        for vuln in cache.lookup(edge):
            findings.append({"package": meta.get("package"), **vuln})
    return {"db_path": db, "packages_checked": len(rows), "findings": findings,
            "imported": imported}
