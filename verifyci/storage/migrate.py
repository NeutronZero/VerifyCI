"""Legacy database canonicalization adapter (P0/P3 follow-through).

Production ingestion has always emitted 64-hex entity ids
(`compute_logical_entity_id`, `compute_revision_entity_id`), so genuine
legacy DBs are already canonical. This adapter exists for the residual
case the strict `GraphBuilder` validation surfaces as INFRA_ERROR:
databases containing non-canonical ids (hand-built rows, synthetic
fixtures persisted to disk, pre-contract imports).

Design rule: the adapter NEVER silently accepts malformed ids into the
graph. It deterministically re-keys them in an explicit, backed-up,
offline migration step; rows it cannot reconcile (empty file paths)
refuse the whole run instead of writing a half-migrated database.

Usage: `python -m verifyci.storage.migrate <db-path> [--no-backup]`
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path


def _is_hex64(value) -> bool:
    import re
    return bool(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value))


def _rekey(kind: str, old: str) -> str:
    """Deterministic canonical replacement: stable across repeated runs,
    distinct per kind so a logical id never collides with a revision id."""
    return hashlib.sha256(f"verifyci-migrate:{kind}:{old}".encode("utf-8")).hexdigest()


def _is_external_row(meta_json) -> bool:
    try:
        meta = json.loads(meta_json) if meta_json else {}
    except Exception:
        return False
    return bool(isinstance(meta, dict) and meta.get("external"))


def canonicalize_database(db_path: str | Path, backup: bool = True) -> dict:
    """Re-key non-canonical ids; remap edge references; report the rest.

    Returns {"remapped_entities": int, "remapped_edges": int,
             "normalized_paths": int, "unmigratable": [str, ...]}.
    Raises ValueError listing unmigratable rows instead of writing a
    half-migrated database.
    """
    db_path = str(db_path)
    if backup:
        shutil.copy2(db_path, db_path + ".bak")
    conn = sqlite3.connect(db_path)
    report: dict = {"remapped_entities": 0, "remapped_edges": 0,
                    "normalized_paths": 0, "unmigratable": []}
    try:
        logical_map: dict[str, str] = {}
        rev_map: dict[str, str] = {}
        rows = conn.execute(
            "SELECT revision_entity_id, logical_entity_id, file_path, metadata_json"
            " FROM entities").fetchall()
        for rev_id, log_id, fpath, meta_json in rows:
            if _is_external_row(meta_json):
                continue  # external placeholders are canonical by design
            # Non-hex ids are exactly what this migration fixes, so they
            # are collected, not refused. An empty file path cannot be
            # reconciled automatically: refuse rather than invent one.
            if not fpath:
                report["unmigratable"].append(
                    f"entity rev={rev_id!r}: empty file_path")
        if report["unmigratable"]:
            raise ValueError(
                "refusing migration with unmigratable rows: "
                + "; ".join(report["unmigratable"][:5]))
        for rev_id, log_id, fpath, _meta in rows:
            meta_flag = False
            try:
                meta_flag = bool((json.loads(_meta) if _meta else {}).get("external"))
            except Exception:
                pass
            if meta_flag:
                continue
            # Only non-canonical ids are re-keyed; healthy rows keep their
            # identity so continuity (supersession, disappearance) survives.
            new_log = log_id if _is_hex64(log_id) else _rekey("logical", log_id)
            new_rev = rev_id if _is_hex64(rev_id) else _rekey("revision", rev_id)
            norm_path = fpath.replace("\\", "/")
            while norm_path.startswith("./"):
                norm_path = norm_path[2:]
            while "//" in norm_path:
                norm_path = norm_path.replace("//", "/")
            if new_log != log_id:
                logical_map[log_id] = new_log
            if new_rev != rev_id:
                rev_map[rev_id] = new_rev
            if (new_log, new_rev, norm_path) == (log_id, rev_id, fpath):
                continue
            conn.execute(
                "UPDATE entities SET logical_entity_id = ?, revision_entity_id = ?,"
                " file_path = ? WHERE revision_entity_id = ? AND logical_entity_id = ?",
                (new_log, new_rev, norm_path, rev_id, log_id))
            report["remapped_entities"] += 1
            if norm_path != fpath:
                report["normalized_paths"] += 1
        for (eid, src, dst) in conn.execute(
                "SELECT id, src_entity_id, dst_entity_id FROM edges").fetchall():
            new_src = rev_map.get(src, src)
            new_dst = rev_map.get(dst, dst) if dst else dst
            if (new_src, new_dst) != (src, dst):
                conn.execute(
                    "UPDATE edges SET src_entity_id = ?, dst_entity_id = ? WHERE id = ?",
                    (new_src, new_dst, eid))
                report["remapped_edges"] += 1
        conn.commit()
    finally:
        conn.close()
    return report


if __name__ == "__main__":
    _db = sys.argv[1] if len(sys.argv) > 1 else None
    if not _db:
        print("usage: python -m verifyci.storage.migrate <db-path> [--no-backup]",
              file=sys.stderr)
        raise SystemExit(2)
    _backup = "--no-backup" not in sys.argv[2:]
    try:
        _rep = canonicalize_database(_db, backup=_backup)
    except ValueError as exc:
        print(f"migration refused: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"migrated {Path(_db).name}: {json.dumps(_rep)}")
