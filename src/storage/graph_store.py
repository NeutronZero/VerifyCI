import json
import sqlite3
from pathlib import Path
from typing import Optional

from src.contracts.entity import Entity, EntityType
from src.contracts.edge import Edge, EdgeType, CPGEdgeSubtype
from src.contracts.revision import Revision


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
    revision_entity_id TEXT PRIMARY KEY,
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
    valid_from REAL,
    valid_until REAL,
    t_created REAL,
    t_expired REAL,
    metadata_json TEXT,
    properties_json TEXT,
    FOREIGN KEY (revision_id) REFERENCES revisions(revision_id)
);
CREATE INDEX IF NOT EXISTS idx_entities_logical ON entities(logical_entity_id);
CREATE INDEX IF NOT EXISTS idx_entities_logical_valid ON entities(logical_entity_id, valid_from, valid_until);

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
"""


class GraphStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._batch_depth = 0

    from contextlib import contextmanager as _cm

    @_cm
    def batch(self):
        """Defer commits until the block exits (bulk ingest path)."""
        self._batch_depth += 1
        try:
            yield self
        finally:
            self._batch_depth -= 1
            if self._batch_depth <= 0:
                self._batch_depth = 0
                self.conn.commit()

    def _maybe_commit(self):
        if self._batch_depth <= 0:
            self.conn.commit()

    def insert_revision(self, revision: Revision):
        self.conn.execute(
            "INSERT OR REPLACE INTO revisions VALUES (?,?,?,?,?,?,?)",
            (revision.revision_id, revision.repository_id, revision.commit_id,
             revision.parent_revision_id, revision.source_hash,
             revision.timestamp, revision.ingestion_config_hash),
        )
        self._maybe_commit()

    def get_latest_revision(self, repository_id: str):
        from src.contracts.revision import Revision
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
        return json.loads(row[0]) if row else None

    def close_deleted_file_version(self, file_path: str, live_logical_ids: list[str],
                                   current_revision_id: str, now: float) -> tuple[int, int]:
        """Close live rows from older revisions for entities of file_path that
        no longer exist, plus edges sourced from the deleted entities."""
        prev = self.conn.execute(
            "SELECT revision_entity_id, logical_entity_id FROM entities"
            " WHERE file_path = ? AND revision_id != ? AND valid_until IS NULL",
            (file_path, current_revision_id),
        ).fetchall()
        live = set(live_logical_ids)
        gone = [(r[0], r[1]) for r in prev if r[1] not in live]
        gone_ids = {r[0] for r in gone}
        for rid in gone_ids:
            self.conn.execute(
                "UPDATE entities SET valid_until = ?, t_expired = ? WHERE revision_entity_id = ?",
                (now, now, rid),
            )
        n_d = 0
        if gone_ids:
            rows = self.conn.execute(
                "SELECT id, src_entity_id FROM edges WHERE revision_id != ? AND valid_until IS NULL",
                (current_revision_id,),
            ).fetchall()
            ids = [r[0] for r in rows if r[1] in gone_ids]
            self.conn.executemany(
                "UPDATE edges SET valid_until = ?, t_expired = ? WHERE id = ?",
                [(now, now, i) for i in ids],
            )
            n_d = len(ids)
        self._maybe_commit()
        return len(gone), n_d

    def close_superseded_entities(self, logical_ids: list[str], current_revision_id: str,
                                  now: float) -> int:
        """Close prior live versions (valid_until/t_expired) superseded by the
        current revision. Returns rows closed."""
        total = 0
        for logical_id in set(logical_ids):
            cur = self.conn.execute(
                "UPDATE entities SET valid_until = ?, t_expired = ?"
                " WHERE logical_entity_id = ? AND revision_id != ?"
                " AND valid_until IS NULL",
                (now, now, logical_id, current_revision_id),
            )
            total += cur.rowcount
        self._maybe_commit()
        return total

    def close_superseded_edges(self, new_edges: list, current_revision_id: str,
                               now: float) -> int:
        """Close prior live edges superseded by the current revision.

        Endpoints embed the revision, so matching is by *logical* identity
        (raw endpoint strings for external/SBOM endpoints).
        """
        ent = {r[0]: r[1] for r in self.conn.execute(
            "SELECT revision_entity_id, logical_entity_id FROM entities").fetchall()}
        targets = set()
        for e in new_edges:
            etype = e.type.value if hasattr(e.type, "value") else e.type
            targets.add((ent.get(e.src_entity_id, e.src_entity_id),
                         ent.get(e.dst_entity_id, e.dst_entity_id), etype))
        rows = self.conn.execute(
            "SELECT id, src_entity_id, dst_entity_id, type FROM edges"
            " WHERE revision_id != ? AND valid_until IS NULL",
            (current_revision_id,),
        ).fetchall()
        ids = [r[0] for r in rows
               if (ent.get(r[1], r[1]), ent.get(r[2], r[2]), r[3]) in targets]
        if ids:
            self.conn.executemany(
                "UPDATE edges SET valid_until = ?, t_expired = ? WHERE id = ?",
                [(now, now, i) for i in ids],
            )
            self._maybe_commit()
        return len(ids)

    def insert_entity(self, entity: Entity):
        self.conn.execute(
            "INSERT OR REPLACE INTO entities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (entity.revision_entity_id, entity.logical_entity_id, entity.repository_id,
             entity.revision_id, entity.type.value, entity.name, entity.file_path,
             entity.line_start, entity.line_end, entity.language, entity.source_hash,
             entity.valid_from, entity.valid_until, entity.t_created, entity.t_expired,
             json.dumps(entity.metadata), entity.properties_json),
        )
        self._maybe_commit()

    def insert_edge(self, edge: Edge):
        self.conn.execute(
            "INSERT OR REPLACE INTO edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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

    def get_entity_by_name(self, name: str, revision_id: Optional[str] = None) -> Optional[Entity]:
        # Without a revision this answers "latest live" deterministically —
        # never an arbitrary row across revisions (revision-scoping audit).
        if revision_id is not None:
            row = self.conn.execute(
                "SELECT * FROM entities WHERE name = ? AND revision_id = ? AND (t_expired IS NULL) LIMIT 1",
                (name, revision_id),
            ).fetchone()
        else:
            row = self.conn.execute(
                "SELECT * FROM entities WHERE name = ? AND (t_expired IS NULL)"
                " ORDER BY valid_from DESC NULLS LAST LIMIT 1",
                (name,),
            ).fetchone()
        return self._row_to_entity(row) if row else None

    def insert_event(self, event) -> None:
        import json as _json
        self.conn.execute(
            "INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?)",
            (event.id, event.type, event.timestamp, event.task_id, event.conversation_id,
             _json.dumps(event.payload or {}), _json.dumps(event.provenance or {}),
             event.prev_event_hash,
             _json.dumps(event.attestation) if getattr(event, "attestation", None) else None),
        )
        self._maybe_commit()

    def get_events(self) -> list:
        rows = self.conn.execute("SELECT * FROM events ORDER BY timestamp ASC").fetchall()
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

    def close(self):
        self.conn.close()

    def _row_to_entity(self, row) -> Entity:
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

    def _row_to_edge(self, row) -> Edge:
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

    def _row_to_event(self, row):
        from src.contracts.event import Event
        return Event(
            id=row[0],
            type=row[1],
            timestamp=row[2],
            task_id=row[3],
            conversation_id=row[4],
            payload=json.loads(row[5]) if row[5] else {},
            provenance=json.loads(row[6]) if row[6] else {},
            prev_event_hash=row[7],
        )
