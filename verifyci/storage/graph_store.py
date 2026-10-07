import json
import sqlite3
from pathlib import Path
from typing import Optional

from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.edge import Edge, EdgeType, CPGEdgeSubtype
from verifyci.contracts.revision import Revision


SCHEMA = """
CREATE TABLE IF NOT EXISTS revisions (
    revision_id TEXT PRIMARY KEY,
    repository_id TEXT NOT NULL,
    commit_id TEXT,
    parent_revision_id TEXT,
    source_hash TEXT NOT NULL,
    timestamp REAL NOT NULL,
    ingestion_config_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
    revision_entity_id TEXT NOT NULL,
    logical_entity_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    language TEXT,
    source_hash TEXT NOT NULL,
    valid_from REAL NOT NULL,
    valid_until REAL,
    t_created REAL,
    t_expired REAL,
    metadata_json TEXT,
    properties_json TEXT,
    PRIMARY KEY (revision_entity_id, valid_from),
    FOREIGN KEY (revision_id) REFERENCES revisions(revision_id)
);
CREATE INDEX IF NOT EXISTS idx_entities_logical ON entities(logical_entity_id);
CREATE INDEX IF NOT EXISTS idx_entities_logical_valid ON entities(logical_entity_id, valid_from, valid_until);
CREATE INDEX IF NOT EXISTS idx_entities_revision ON entities(revision_id);
CREATE INDEX IF NOT EXISTS idx_entities_path ON entities(file_path);
CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);

CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL,
    src_entity_id TEXT NOT NULL,
    dst_entity_id TEXT NOT NULL,
    type TEXT NOT NULL,
    subtype TEXT,
    valid_from REAL,
    valid_until REAL,
    observed_at REAL,
    source_commit TEXT,
    t_created REAL,
    t_expired REAL,
    metadata_json TEXT,
    properties_json TEXT,
    FOREIGN KEY (revision_id) REFERENCES revisions(revision_id)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_revision ON edges(revision_id);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    task_id TEXT,
    conversation_id TEXT,
    payload_json TEXT NOT NULL,
    provenance_json TEXT NOT NULL,
    prev_event_hash TEXT,
    attestation_json TEXT
);

CREATE TABLE IF NOT EXISTS anchors (
    anchor_id TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS deltas (
    delta_id TEXT PRIMARY KEY,
    from_revision_id TEXT NOT NULL,
    to_revision_id TEXT NOT NULL,
    delta_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ingests (
    ingest_id TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    parent_ingest_id TEXT,
    commit_id TEXT,
    timestamp REAL NOT NULL,
    branch TEXT
);
CREATE INDEX IF NOT EXISTS idx_ingests_repo ON ingests(repository_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_ingests_branch ON ingests(repository_id, branch, timestamp);
"""


def _edge_match_key(src_logic: str, dst_logic: str, etype: str,
                    metadata: dict | None) -> tuple:
    # Match key for supersession/disappearance. Unresolved references
    # share one endpoint (dst "") per caller, so the referenced name
    # (callee/base) is part of the key: without it, removing one call
    # while another remains reads as continuing and the removed row
    # stays live forever.
    if etype in ("CALLS_UNRESOLVED", "INHERITS_UNRESOLVED"):
        meta = metadata or {}
        return (src_logic, dst_logic, etype,
                meta.get("callee") or meta.get("base") or "")
    return (src_logic, dst_logic, etype)


def latest_revision_id(conn, repository_id: str | None = None, branch: str | None = None) -> str:
    """Latest ingested revision id for raw connections, scoped when
    possible.

    Reads the append-only ``ingests`` chain (insertion order), so a
    revert (old content reappearing) correctly reports the old revision
    as latest — ordering by the immutable ``revisions.timestamp`` would
    freeze "latest" at first observation. Falls back to the
    ``revisions`` table for DBs written before the ingest log existed.

    Read-only paths (stats, vuln) must not construct a store — that
    would mkdir and schema-write at client-chosen paths. Same
    repo-then-global rule as the method form, with one guard: when a
    repository IS known (convention-derived) but the ingest lineage
    holds other repos' rows and none of its own, return "" instead of
    falling back to global — in a shared DB a renamed or moved
    checkout must not silently verify against another repository's
    latest revision. Global fallback applies only when no repository
    applies at all (custom paths, legacy callers), and the revisions
    table still answers when the ingest log is empty (legacy/test
    DBs written without ingest rows).
    """
    ingests_live = _has_table(conn, "ingests") and conn.execute(
        "SELECT 1 FROM ingests LIMIT 1").fetchone() is not None
    if ingests_live:
        if repository_id:
            if branch:
                row = conn.execute(
                    "SELECT revision_id FROM ingests WHERE repository_id = ? AND branch = ?"
                    " ORDER BY timestamp DESC, rowid DESC LIMIT 1",
                    (repository_id, branch),
                ).fetchone()
                if row:
                    return row[0]
            row = conn.execute(
                "SELECT revision_id FROM ingests WHERE repository_id = ?"
                " ORDER BY timestamp DESC, rowid DESC LIMIT 1",
                (repository_id,),
            ).fetchone()
            return row[0] if row else ""
        row = conn.execute(
            "SELECT revision_id FROM ingests"
            " ORDER BY timestamp DESC, rowid DESC LIMIT 1"
        ).fetchone()
        if row:
            return row[0]
    if repository_id:
        row = conn.execute(
            "SELECT revision_id FROM revisions WHERE repository_id = ?"
            " ORDER BY timestamp DESC LIMIT 1",
            (repository_id,),
        ).fetchone()
        return row[0] if row else ""
    row = conn.execute(
        "SELECT revision_id FROM revisions ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()
    return row[0] if row else ""


def _has_table(conn, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _migrate_v0_to_v1(conn: sqlite3.Connection) -> None:
    # No-op: v0 is the baseline pre-composite-key schema at commit 451b551.
    pass


def _migrate_v1_to_v2(conn: sqlite3.Connection) -> None:
    # Forward-compatible composite key migration for S-01.
    # Note: Cannot restore previously overwritten deletion intervals from raw state.
    old_isolation = conn.isolation_level
    conn.isolation_level = None  # Autocommit mode for explicit transaction control
    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.execute("BEGIN TRANSACTION;")
    try:
        conn.execute("""
            CREATE TABLE entities_v2 (
                revision_entity_id TEXT NOT NULL,
                logical_entity_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                revision_id TEXT NOT NULL,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_start INTEGER,
                line_end INTEGER,
                language TEXT,
                source_hash TEXT NOT NULL,
                valid_from REAL NOT NULL,
                valid_until REAL,
                t_created REAL,
                t_expired REAL,
                metadata_json TEXT,
                properties_json TEXT,
                PRIMARY KEY (revision_entity_id, valid_from),
                FOREIGN KEY (revision_id) REFERENCES revisions(revision_id)
            );
        """)
        conn.execute("INSERT INTO entities_v2 SELECT * FROM entities;")
        conn.execute("DROP TABLE entities;")
        conn.execute("ALTER TABLE entities_v2 RENAME TO entities;")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_logical ON entities(logical_entity_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_logical_valid ON entities(logical_entity_id, valid_from, valid_until);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_revision ON entities(revision_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_path ON entities(file_path);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);")
        conn.execute("PRAGMA user_version = 2;")
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.isolation_level = old_isolation


class GraphStore:
    def __init__(self, db_path: str, read_only: bool = False):
        self.db_path = db_path
        if read_only:
            # Verification/query readers must never construct a writing
            # store: mkdir + PRAGMA journal_mode=WAL + schema script are
            # writes, and on a read-only checkout/CI mount a WAL-mode DB
            # cannot even be OPENED read-write (no -shm). mode=ro opens
            # the committed state without touching the file or its
            # directory; failures surface as sqlite errors for the
            # caller to classify (InfraError), never as an empty graph.
            # (WAL + mode=ro works when the -shm/-wal sidecars exist or
            # the directory is writable; on a sealed read-only mount
            # the DB must have been checkpointed/closed cleanly.)
            import sqlite3 as _sqlite3
            from pathlib import Path as _Path
            uri = _Path(db_path).resolve().as_uri() + "?mode=ro"
            self.conn = _sqlite3.connect(uri, uri=True, timeout=2.0)
            try:
                self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
            except BaseException:
                # Construction failed after connecting (locked/corrupt):
                # the half-open connection must not leak to GC — and the
                # caller never receives a store to close.
                self.conn.close()
                raise
            self._batch_depth = 0
            return
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        # Foreign keys are per-connection in SQLite (default OFF): the
        # writer must opt in or revision/ingest links go unchecked.
        # Reader connections stay untouched; the v1->v2 migration still
        # toggles explicitly around its table rebuild.
        self.conn.execute("PRAGMA foreign_keys=ON")
        # WAL: a long ingest transaction no longer blocks readers —
        # verify/stats/query see the last committed revision instead of
        # "database is locked" (which, pre-fix, surfaced as a
        # masquerading INCONCLUSIVE). Set BEFORE the schema script:
        # journal_mode is persistent, so a fresh DB keeps it and readers
        # (open_for_read) can rely on it. Deliberate side effect: EVERY
        # writer construction flips the file header to WAL, including
        # tests in tmpdirs — there is no "no writes on read paths"
        # invariant for writers, only for readers (read_only=True,
        # which skips this pragma entirely).
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            table_exists = self.conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='entities'"
            ).fetchone() is not None
            if not table_exists:
                self.conn.executescript(SCHEMA)
                self.conn.execute("PRAGMA user_version = 2;")
                self.conn.commit()
            else:
                v = self.conn.execute("PRAGMA user_version;").fetchone()[0]
                if v < 1:
                    _migrate_v0_to_v1(self.conn)
                if v < 2:
                    _migrate_v1_to_v2(self.conn)
                if _has_table(self.conn, "ingests"):
                    cols = [r[1] for r in self.conn.execute("PRAGMA table_info(ingests)").fetchall()]
                    if "branch" not in cols:
                        self.conn.execute("ALTER TABLE ingests ADD COLUMN branch TEXT;")
                        self.conn.execute(
                            "CREATE INDEX IF NOT EXISTS idx_ingests_branch ON ingests(repository_id, branch, timestamp);"
                        )
                        self.conn.commit()
        except BaseException:
            # Same half-open guarantee as the read-only path above.
            self.conn.close()
            raise
        self._batch_depth = 0

    from contextlib import contextmanager as _cm

    @_cm
    def batch(self):
        """Defer commits until the block exits (bulk ingest path).

        An exception rolls back instead of committing: the old
        commit-in-finally left half-populated revisions behind, and the
        "latest revision" loader then served the wreckage to every
        command. Partial ingest data is never loadable.
        """
        self._batch_depth += 1
        try:
            yield self
        except BaseException:
            self._batch_depth -= 1
            if self._batch_depth <= 0:
                self._batch_depth = 0
                self.conn.rollback()
            raise
        else:
            self._batch_depth -= 1
            if self._batch_depth <= 0:
                self._batch_depth = 0
                self.conn.commit()

    def _maybe_commit(self):
        if self._batch_depth <= 0:
            self.conn.commit()

    def insert_revision(self, revision: Revision):
        # Immutable: identical content is one row forever. A later
        # ingest must never rewrite an existing revision's commit or
        # parent — that is how a revert used to create a parent cycle.
        self.conn.execute(
            "INSERT OR IGNORE INTO revisions VALUES (?,?,?,?,?,?,?)",
            (revision.revision_id, revision.repository_id, revision.commit_id,
             revision.parent_revision_id, revision.source_hash,
             revision.timestamp, revision.ingestion_config_hash),
        )
        self._maybe_commit()

    def insert_ingest(self, ingest) -> None:
        """Append one ingest event (lineage chain, never rewritten)."""
        branch = getattr(ingest, "branch", None)
        self.conn.execute(
            "INSERT INTO ingests (ingest_id, revision_id, repository_id, parent_ingest_id, commit_id, timestamp, branch)"
            " VALUES (?,?,?,?,?,?,?)",
            (ingest.ingest_id, ingest.revision_id, ingest.repository_id,
             ingest.parent_ingest_id, ingest.commit_id, ingest.timestamp, branch),
        )
        self._maybe_commit()

    def latest_revision_id(self, repository_id: str | None = None, branch: str | None = None) -> str:
        """Latest revision id, scoped to a repository when known.

        A global MAX(timestamp) across repository ids lets one repo's
        ingest hijack every other repo's commands sharing the file.
        Callers pass the convention-derived repo (`resolve_repository`)
        and fall back to global only when no convention applies.
        """
        return latest_revision_id(self.conn, repository_id, branch=branch)

    def latest_ingest_id(self, repository_id: str, branch: Optional[str] = None) -> str:
        if branch:
            row = self.conn.execute(
                "SELECT ingest_id FROM ingests WHERE repository_id = ? AND branch = ?"
                " ORDER BY timestamp DESC, rowid DESC LIMIT 1",
                (repository_id, branch),
            ).fetchone()
            if row:
                return row[0]
        row = self.conn.execute(
            "SELECT ingest_id FROM ingests WHERE repository_id = ?"
            " ORDER BY timestamp DESC, rowid DESC LIMIT 1",
            (repository_id,),
        ).fetchone()
        return row[0] if row else ""

    def latest_ingest_on_branch(self, repository_id: str, branch: str) -> str:
        row = self.conn.execute(
            "SELECT ingest_id FROM ingests WHERE repository_id = ? AND branch = ?"
            " ORDER BY timestamp DESC, rowid DESC LIMIT 1",
            (repository_id, branch),
        ).fetchone()
        return row[0] if row else ""

    def get_ingest_by_commit_id(self, repository_id: str, commit_id: str):
        from verifyci.contracts.revision import Ingest
        row = self.conn.execute(
            "SELECT ingest_id, revision_id, repository_id, parent_ingest_id, commit_id, timestamp, branch"
            " FROM ingests WHERE repository_id = ? AND commit_id = ?"
            " ORDER BY timestamp DESC, rowid DESC LIMIT 1",
            (repository_id, commit_id),
        ).fetchone()
        if not row:
            return None
        return Ingest(
            ingest_id=row[0],
            revision_id=row[1],
            repository_id=row[2],
            parent_ingest_id=row[3],
            commit_id=row[4],
            timestamp=row[5],
            branch=row[6] if len(row) > 6 else None,
        )

    def get_revision_by_commit_id(self, repository_id: str, commit_id: str) -> Optional[str]:
        row = self.conn.execute(
            "SELECT revision_id FROM ingests WHERE repository_id = ? AND commit_id = ?"
            " ORDER BY timestamp DESC, rowid DESC LIMIT 1",
            (repository_id, commit_id),
        ).fetchone()
        if row and row[0]:
            return row[0]
        row = self.conn.execute(
            "SELECT revision_id FROM revisions WHERE repository_id = ? AND commit_id = ?"
            " ORDER BY timestamp DESC LIMIT 1",
            (repository_id, commit_id),
        ).fetchone()
        return row[0] if row else None

    def get_latest_revision(self, repository_id: str):
        from verifyci.contracts.revision import Revision
        # Route through the append-only ingests chain (same rule as
        # latest_revision_id): ordering revisions by timestamp freezes
        # "latest" at first observation, so a revert (old content
        # reappearing) would never report the old revision as latest.
        # Falls back to timestamp ordering only when the ingest log is
        # empty (legacy/test DBs without ingest rows).
        rev_id = latest_revision_id(self.conn, repository_id)
        if rev_id:
            row = self.conn.execute(
                "SELECT * FROM revisions WHERE revision_id = ?",
                (rev_id,),
            ).fetchone()
            if row is not None:
                return Revision(
                    revision_id=row[0], repository_id=row[1], commit_id=row[2],
                    parent_revision_id=row[3], source_hash=row[4], timestamp=row[5],
                    ingestion_config_hash=row[6],
                )
        row = self.conn.execute(
            "SELECT * FROM revisions WHERE repository_id = ? ORDER BY timestamp DESC LIMIT 1",
            (repository_id,),
        ).fetchone()
        if row is None:
            return None
        return Revision(
            revision_id=row[0], repository_id=row[1], commit_id=row[2],
            parent_revision_id=row[3], source_hash=row[4], timestamp=row[5],
            ingestion_config_hash=row[6],
        )

    def insert_anchor(self, revision_id: str, snapshot: dict) -> str:
        import time as _time
        anchor_id = f"anchor_{revision_id[:12]}"
        self.conn.execute(
            "INSERT OR REPLACE INTO anchors VALUES (?,?,?,?)",
            (anchor_id, revision_id, json.dumps(snapshot, sort_keys=True),
             _time.time()),
        )
        self._maybe_commit()
        return anchor_id

    def insert_delta(self, from_revision_id: str, to_revision_id: str, delta: dict) -> str:
        delta_id = f"delta_{from_revision_id[:8]}_{to_revision_id[:8]}"
        self.conn.execute(
            "INSERT OR REPLACE INTO deltas VALUES (?,?,?,?)",
            (delta_id, from_revision_id, to_revision_id,
             json.dumps(delta, sort_keys=True)),
        )
        self._maybe_commit()
        return delta_id

    def get_anchor(self, revision_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT snapshot_json FROM anchors WHERE revision_id = ? ORDER BY timestamp DESC LIMIT 1",
            (revision_id,),
        ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception as exc:
            from verifyci.contracts.revision import LineageIntegrityError
            raise LineageIntegrityError(
                f"Corrupted anchor snapshot record in storage for revision {revision_id}: {exc}"
            ) from exc

    def close_disappeared(self, current_revision_id: str, parent_revision_id: str,
                            repository_id: str, now: float) -> tuple[int, int]:
        """Expire entities and edges the new revision no longer contains.

        Supersession closes what was re-observed; this closes what
        vanished: entities whose logical id has no row in the current
        revision (deleted/renamed files and functions), and live edges
        whose endpoint-pair no longer exists (removed calls). Without
        it, `get_entity_by_name` and graph loads return ghosts of
        deleted code indefinitely. Returns (entities, edges) closed.

        Scoped to parent revision and repository: multi-repo and multi-branch
        DBs must not expire each other's rows. Skips when there is no parent
        (fresh or same-state ingest — nothing could have disappeared). Carried
        unresolved references are present in the new revision (re-
        inserted by carry-forward), so they read as continuing, not
        disappeared — no special-casing.
        """
        if not parent_revision_id:
            return 0, 0
        cur = self.conn.execute(
            "UPDATE entities SET valid_until = ?, t_expired = ?"
            " WHERE revision_id != ? AND repository_id = ?"
            " AND valid_until IS NULL"
            " AND logical_entity_id IN ("
            " SELECT logical_entity_id FROM entities WHERE revision_id = ?)"
            " AND logical_entity_id NOT IN ("
            " SELECT logical_entity_id FROM entities WHERE revision_id = ?)",
            (now, now, current_revision_id, repository_id, parent_revision_id, current_revision_id),
        )
        n_entities = cur.rowcount
        entmap = {
            r[0]: r[1] for r in self.conn.execute(
                "SELECT revision_entity_id, logical_entity_id FROM entities"
                " WHERE revision_id IN (SELECT revision_id FROM revisions"
                " WHERE repository_id = ?)",
                (repository_id,)).fetchall()
        }
        new_keys = set()
        for r in self.conn.execute(
                "SELECT src_entity_id, dst_entity_id, type, metadata_json FROM edges"
                " WHERE revision_id = ?", (current_revision_id,)).fetchall():
            meta = json.loads(r[3]) if r[3] else {}
            new_keys.add(_edge_match_key(entmap.get(r[0], r[0]),
                                         entmap.get(r[1], r[1]), r[2], meta))
        old = self.conn.execute(
            "SELECT id, src_entity_id, dst_entity_id, type, metadata_json FROM edges"
            " WHERE revision_id = ? AND valid_until IS NULL",
            (parent_revision_id,)).fetchall()
        gone = []
        for r in old:
            meta = json.loads(r[4]) if r[4] else {}
            if _edge_match_key(entmap.get(r[1], r[1]), entmap.get(r[2], r[2]),
                               r[3], meta) not in new_keys:
                gone.append(r[0])
        if gone:
            self.conn.executemany(
                "UPDATE edges SET valid_until = ?, t_expired = ? WHERE id = ?",
                [(now, now, i) for i in gone],
            )
        self._maybe_commit()
        return n_entities, len(gone)

    def close_superseded_entities(self, logical_ids: list[str], current_revision_id: str,
                                   now: float, repository_id: Optional[str] = None) -> int:
        """Close prior live versions (valid_until/t_expired) superseded by the
        current revision. Chunked UPDATEs to avoid SQLITE_MAX_VARIABLE_NUMBER. Returns rows closed.
        Scoped by repository_id when provided so multi-repo DBs never close
        each other's live rows."""
        ids = list(set(logical_ids))
        if not ids:
            return 0
        total_closed = 0
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            placeholders = ",".join("?" for _ in chunk)
            sql = (
                "UPDATE entities SET valid_until = ?, t_expired = ?"
                f" WHERE logical_entity_id IN ({placeholders}) AND revision_id != ?"
                " AND valid_until IS NULL"
            )
            params: list = [now, now, *chunk, current_revision_id]
            if repository_id:
                sql += " AND repository_id = ?"
                params.append(repository_id)
            cur = self.conn.execute(sql, params)
            total_closed += cur.rowcount
        self._maybe_commit()
        return total_closed

    def close_superseded_edges(self, new_edges: list, current_revision_id: str,
                               now: float, repository_id: Optional[str] = None) -> int:
        """Close prior live edges superseded by the current revision.

        Endpoints embed the revision, so matching is by *logical* identity
        (raw endpoint strings for external/SBOM endpoints). Candidate
        loading stays scoped to the new edges' endpoint set (one file's
        fan-out, in practice): loading the whole repository's entities
        and live edges on every file made re-ingest quadratic.
        """
        if not new_edges:
            return 0
        ent: dict[str, str] = {}
        endpoints = sorted({x for e in new_edges
                            for x in (e.src_entity_id, e.dst_entity_id) if x})
        for i in range(0, len(endpoints), 500):
            chunk = endpoints[i:i + 500]
            placeholders = ",".join("?" for _ in chunk)
            sql = ("SELECT revision_entity_id, logical_entity_id FROM entities"
                   f" WHERE revision_entity_id IN ({placeholders})")
            params: list = list(chunk)
            if repository_id:
                sql += " AND repository_id = ?"
                params.append(repository_id)
            for r in self.conn.execute(sql, params).fetchall():
                ent[r[0]] = r[1]

        def _logic(x: str) -> str:
            return ent.get(x, x)

        targets = set()
        for e in new_edges:
            etype = e.type.value if hasattr(e.type, "value") else e.type
            targets.add(_edge_match_key(_logic(e.src_entity_id),
                                        _logic(e.dst_entity_id), etype,
                                        getattr(e, "metadata", None)))
        touched = sorted({_logic(x) for x in endpoints})
        cand_ids: set[str] = set()
        for i in range(0, len(touched), 500):
            chunk = touched[i:i + 500]
            placeholders = ",".join("?" for _ in chunk)
            sql = ("SELECT revision_entity_id, logical_entity_id FROM entities"
                   f" WHERE logical_entity_id IN ({placeholders})")
            params = list(chunk)
            if repository_id:
                sql += " AND repository_id = ?"
                params.append(repository_id)
            for r in self.conn.execute(sql, params).fetchall():
                cand_ids.add(r[0])
                ent[r[0]] = r[1]
        # External endpoints (manifest paths, SBOM ids, "") have no
        # entity row; match them verbatim.
        cand_ids.update(x for x in endpoints if x not in ent)
        edge_rows: list = []
        cand = sorted(cand_ids)
        for i in range(0, len(cand), 500):
            chunk = cand[i:i + 500]
            placeholders = ",".join("?" for _ in chunk)
            sql = ("SELECT id, src_entity_id, dst_entity_id, type, metadata_json"
                   " FROM edges WHERE revision_id != ? AND valid_until IS NULL"
                   f" AND (src_entity_id IN ({placeholders})"
                   f" OR dst_entity_id IN ({placeholders}))")
            params = [current_revision_id, *chunk, *chunk]
            if repository_id:
                sql += (" AND revision_id IN (SELECT revision_id FROM revisions"
                        " WHERE repository_id = ?)")
                params.append(repository_id)
            edge_rows.extend(self.conn.execute(sql, params).fetchall())
        ids = []
        for r in edge_rows:
            meta = json.loads(r[4]) if r[4] else {}
            if _edge_match_key(ent.get(r[1], r[1]), ent.get(r[2], r[2]),
                               r[3], meta) in targets:
                ids.append(r[0])
        if ids:
            for i in range(0, len(ids), 500):
                chunk = ids[i:i + 500]
                self.conn.executemany(
                    "UPDATE edges SET valid_until = ?, t_expired = ? WHERE id = ?",
                    [(now, now, i) for i in chunk],
                )
            self._maybe_commit()
        return len(ids)

    def insert_entity(self, entity: Entity):
        # A recorded revision-fact is immutable: revision_entity_id keys
        # (repository, logical, revision), so re-ingesting the same
        # content yields the SAME id. INSERT OR REPLACE used to rewrite
        # valid_from/t_created to the newest observation, which destroyed
        # the ability to query the previously ingested state as-of an
        # earlier transaction time (bitemporal invariant, V1 Phase 1
        # gate). ON CONFLICT keeps the first-observation stamps and
        # refreshes only the close stamps: valid_until/t_expired come
        # from the incoming row (None on a fresh observation, which
        # re-opens a row that a supersede had closed — the revert cycle
        # A->B->A asserts A current again). Content-derived fields cannot
        # differ under the same id: the revision hash fixes them.
        # S-01: One row per valid-time interval. If this revision entity is
        # already open (valid_until IS NULL), reuse its valid_from to ensure
        # re-ingesting unchanged content does not create duplicate live intervals.
        # If it was previously closed (e.g. revert cycle), a fresh interval is inserted.
        existing = self.conn.execute(
            "SELECT valid_from FROM entities WHERE revision_entity_id = ? AND valid_until IS NULL",
            (entity.revision_entity_id,)
        ).fetchone()
        if existing is not None:
            v_from = existing[0]
        else:
            v_from = entity.valid_from if entity.valid_from is not None else (entity.t_created if entity.t_created is not None else 0.0)
        self.conn.execute(
            "INSERT INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(revision_entity_id, valid_from) DO UPDATE SET"
            "   valid_until = excluded.valid_until,"
            "   t_expired   = excluded.t_expired",
            (entity.revision_entity_id, entity.logical_entity_id, entity.repository_id,
             entity.revision_id, entity.type.value, entity.name, entity.file_path,
             entity.line_start, entity.line_end, entity.language, entity.source_hash,
             v_from, entity.valid_until, entity.t_created, entity.t_expired,
             json.dumps(entity.metadata), entity.properties_json),
        )
        self._maybe_commit()

    def insert_edge(self, edge: Edge):
        # Same discipline as insert_entity: edge ids embed the revision
        # (and the referenced name for unresolved refs), so a re-ingest
        # of identical content re-observes the identical fact. Keep the
        # first valid_from/t_created/observed_at; re-open on re-assertion.
        self.conn.execute(
            "INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(id) DO UPDATE SET"
            "   valid_until = excluded.valid_until,"
            "   t_expired   = excluded.t_expired",
            (edge.id, edge.revision_id, edge.src_entity_id, edge.dst_entity_id,
             edge.type.value, edge.subtype.value if edge.subtype else None,
             edge.valid_from, edge.valid_until, edge.observed_at, edge.source_commit,
             edge.t_created, edge.t_expired, json.dumps(edge.metadata), edge.properties_json),
        )
        self._maybe_commit()

    def get_entity_by_logical(self, logical_entity_id: str, asOf: Optional[float] = None) -> Optional[Entity]:
        if asOf is not None:
            return self.get_entity_as_of(logical_entity_id, asOf)
        return self.get_current_entity(logical_entity_id)

    def get_entity_as_of(self, logical_entity_id: str, as_of: float) -> Optional[Entity]:
        """Valid-time travel: which version held at time ``as_of``.

        Decided by [valid_from, valid_until) only. Transaction-time expiry
        (t_expired) is deliberately NOT consulted — retraction must not hide
        history. Separate method from latest-version lookup so the two time
        semantics cannot re-merge into one WHERE clause.
        """
        row = self.conn.execute(
            "SELECT * FROM entities WHERE logical_entity_id = ?"
            " AND (valid_from IS NULL OR valid_from <= ?)"
            " AND (valid_until IS NULL OR valid_until > ?)"
            " ORDER BY valid_from DESC NULLS LAST LIMIT 1",
            (logical_entity_id, as_of, as_of),
        ).fetchone()
        return self._row_to_entity(row) if row else None

    def get_current_entity(self, logical_entity_id: str) -> Optional[Entity]:
        """Latest live version: never retracted (t_expired IS NULL)."""
        row = self.conn.execute(
            "SELECT * FROM entities WHERE logical_entity_id = ? AND (t_expired IS NULL)"
            " ORDER BY valid_from DESC NULLS LAST LIMIT 1",
            (logical_entity_id,),
        ).fetchone()
        return self._row_to_entity(row) if row else None

    def get_entity_by_name(self, name: str, revision_id: Optional[str] = None,
                           as_of: Optional[float] = None,
                           repository_id: Optional[str] = None) -> Optional[Entity]:
        # Without a revision this answers "latest live" deterministically —
        # never an arbitrary row across revisions (revision-scoping audit).
        # With as_of it answers valid-time travel instead, so renamed or
        # deleted names resolve per timestamp rather than to the live row.
        # repository_id scopes all three branches so a shared multi-repo DB
        # never resolves a name against another repository's rows.
        if revision_id is not None:
            sql = "SELECT * FROM entities WHERE name = ? AND revision_id = ?"
            params: list = [name, revision_id]
            if repository_id:
                sql += " AND repository_id = ?"
                params.append(repository_id)
            row = self.conn.execute(sql + " LIMIT 1", params).fetchone()
        elif as_of is not None:
            sql = (
                "SELECT * FROM entities WHERE name = ?"
                " AND (valid_from IS NULL OR valid_from <= ?)"
                " AND (valid_until IS NULL OR valid_until > ?)"
            )
            params = [name, as_of, as_of]
            if repository_id:
                sql += " AND repository_id = ?"
                params.append(repository_id)
            row = self.conn.execute(
                sql + " ORDER BY valid_from DESC NULLS LAST LIMIT 1",
                params,
            ).fetchone()
        else:
            sql = "SELECT * FROM entities WHERE name = ? AND (t_expired IS NULL)"
            params = [name]
            if repository_id:
                sql += " AND repository_id = ?"
                params.append(repository_id)
            row = self.conn.execute(
                sql + " ORDER BY valid_from DESC NULLS LAST LIMIT 1",
                params,
            ).fetchone()
        return self._row_to_entity(row) if row else None

    def insert_event(self, event) -> None:
        self.insert_events([event])

    def insert_events(self, events: list) -> None:
        if not events:
            return
        import json as _json
        import dataclasses
        rows = []
        for event in events:
            att = getattr(event, "attestation", None)
            if att is not None:
                if dataclasses.is_dataclass(att):
                    att_json = _json.dumps(dataclasses.asdict(att))
                elif hasattr(att, "__dict__"):
                    att_json = _json.dumps(att.__dict__)
                else:
                    att_json = _json.dumps(att)
            else:
                att_json = None
            rows.append((
                event.id, event.type, event.timestamp, event.task_id, event.conversation_id,
                _json.dumps(event.payload or {}), _json.dumps(event.provenance or {}),
                event.prev_event_hash,
                att_json,
            ))
        self.conn.executemany(
            "INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
        self._maybe_commit()

    def get_events(self) -> list:
        # rowid order: stable insertion order. Timestamp ordering
        # re-sorts same-tick appends (coarse Windows clocks) and any
        # backdated row, so reloaded chains would not reproduce. IGNORE
        # (not REPLACE) on insert: re-persisting an id must not move or
        # clobber the stored row.
        rows = self.conn.execute(
            "SELECT * FROM events ORDER BY rowid ASC").fetchall()
        return [self._row_to_event(r) for r in rows]

    def get_entities_by_revision(self, revision_id: str) -> list[Entity]:
        rows = self.conn.execute(
            "SELECT * FROM entities WHERE revision_id = ?", (revision_id,)
        ).fetchall()
        return [self._row_to_entity(r) for r in rows]

    def get_edges_by_revision(self, revision_id: str) -> list[Edge]:
        rows = self.conn.execute(
            "SELECT * FROM edges WHERE revision_id = ?", (revision_id,)
        ).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def repair_duplicate_live_intervals(
            self, repository_id: str, now: float) -> tuple[int, int]:
        """Close stale duplicate live intervals (self-healing invariant).

        At most one live row may exist per logical entity id, and per
        logical edge key. Re-opened rows (a re-asserted id clearing a
        close stamp) and missed closes otherwise leave two live
        intervals for one fact, and every "latest" lookup then answers
        ambiguously. Keeps the latest valid_from per bucket and
        version-closes the rest. Returns (entities, edges) closed.

        Edge buckets are the supersession match key plus the call-site
        suffix from the edge id: parallel call sites share
        (src, dst, type) legitimately and must not collapse into one.
        """
        entity_updates = []
        dup_ids = self.conn.execute(
            "SELECT logical_entity_id FROM entities"
            " WHERE valid_until IS NULL AND repository_id = ?"
            " GROUP BY logical_entity_id HAVING COUNT(*) > 1",
            (repository_id,),
        ).fetchall()
        for (lid,) in dup_ids:
            rows = self.conn.execute(
                "SELECT rowid FROM entities"
                " WHERE logical_entity_id = ? AND valid_until IS NULL"
                " AND repository_id = ?"
                " ORDER BY valid_from DESC, rowid DESC",
                (lid, repository_id),
            ).fetchall()
            for (rid,) in rows[1:]:
                entity_updates.append((now, now, rid))
        if entity_updates:
            self.conn.executemany(
                "UPDATE entities SET valid_until = ?, t_expired = ?"
                " WHERE rowid = ?",
                entity_updates,
            )
        n_entities = len(entity_updates)
        entmap = {
            r[0]: r[1] for r in self.conn.execute(
                "SELECT revision_entity_id, logical_entity_id FROM entities"
                " WHERE revision_id IN (SELECT revision_id FROM revisions"
                " WHERE repository_id = ?)",
                (repository_id,)).fetchall()
        }
        live = self.conn.execute(
            "SELECT id, src_entity_id, dst_entity_id, type, metadata_json,"
            " valid_from FROM edges WHERE valid_until IS NULL"
            " AND revision_id IN (SELECT revision_id FROM revisions"
            " WHERE repository_id = ?)",
            (repository_id,),
        ).fetchall()
        buckets: dict[tuple, list] = {}
        for r in live:
            meta = json.loads(r[4]) if r[4] else {}
            site = ""
            if r[0]:
                last = r[0].rsplit("_", 1)[-1]
                if ":" in last:
                    site = last
            key = _edge_match_key(entmap.get(r[1], r[1]),
                                  entmap.get(r[2], r[2]), r[3], meta) + (site,)
            buckets.setdefault(key, []).append(r)
        edge_updates = []
        for rows in buckets.values():
            if len(rows) < 2:
                continue
            rows.sort(key=lambda r: (r[5] if r[5] is not None else -1.0, r[0]),
                      reverse=True)
            for r in rows[1:]:
                edge_updates.append((now, now, r[0]))
        if edge_updates:
            self.conn.executemany(
                "UPDATE edges SET valid_until = ?, t_expired = ?"
                " WHERE id = ?",
                edge_updates,
            )
        n_edges = len(edge_updates)
        if n_entities or n_edges:
            self._maybe_commit()
        return n_entities, n_edges

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def _row_to_entity(row) -> Entity:
        return Entity(
            repository_id=row[2],
            logical_entity_id=row[1],
            revision_entity_id=row[0],
            type=EntityType(row[4]),
            name=row[5],
            file_path=row[6],
            line_start=row[7],
            line_end=row[8],
            language=row[9],
            source_hash=row[10],
            revision_id=row[3],
            valid_from=row[11],
            valid_until=row[12],
            t_created=row[13],
            t_expired=row[14],
            metadata=json.loads(row[15]) if row[15] else {},
            properties_json=row[16],
        )

    @staticmethod
    def _row_to_edge(row) -> Edge:
        return Edge(
            id=row[0],
            revision_id=row[1],
            src_entity_id=row[2],
            dst_entity_id=row[3],
            type=EdgeType(row[4]),
            subtype=CPGEdgeSubtype(row[5]) if row[5] else None,
            valid_from=row[6],
            valid_until=row[7],
            observed_at=row[8],
            source_commit=row[9],
            t_created=row[10],
            t_expired=row[11],
            metadata=json.loads(row[12]) if row[12] else {},
            properties_json=row[13],
        )

    @staticmethod
    def _row_to_event(row):
        from verifyci.contracts.event import AttestationMetadata, Event
        attestation = None
        if len(row) > 8 and row[8]:
            data = json.loads(row[8])
            if isinstance(data, dict):
                attestation = AttestationMetadata(**data)
        return Event(
            id=row[0],
            type=row[1],
            timestamp=row[2],
            task_id=row[3],
            conversation_id=row[4],
            payload=json.loads(row[5]) if row[5] else {},
            provenance=json.loads(row[6]) if row[6] else {},
            prev_event_hash=row[7],
            attestation=attestation,
        )
