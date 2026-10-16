"""Protocol test substrate for CAP-008 concurrency attestation.

**This is not the VerifyCI system of record.** The product store is DuckDB
(`verifyci_v2/store/duckdb_cpg.py`), per the architecture spec's single-store
invariant. This module exists only because the frozen `worker_protocol.json`
prescribes SQLite semantics (`journal_mode=WAL`, `busy_timeout=5000`) for its
multi-process contention cases.

That prescription cannot be satisfied by DuckDB: DuckDB takes a single writer,
so it cannot exercise write contention, lock exhaustion or torn reads at all.
Running this corpus against DuckDB would make its tripwires unfalsifiable -
they would trivially pass because contention cannot occur. The substrate is
therefore SQLite, confined here to the benchmark tree so it is not mistaken for
a supported product store.

CAP-008 requires a store that several OS processes can write concurrently
while a reader observes a consistent snapshot. SQLite in WAL mode with a busy
timeout is the smallest correct substrate.

Canonicalisation follows the frozen protocol: a revision's `canonical_hash` is
the SHA-256 of a canonical JSON projection of its identity and its entities and
edges, so the same logical content hashes identically regardless of the order in
which concurrent writers happened to commit.

**Fail-closed:** a ledger whose hash chain does not verify, or a revision
observed mid-write, is reported as inconclusive rather than as a pass.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import Any, Iterable

#: Pragmas mandated by the frozen worker protocol.
#: ORDER IS SIGNIFICANT: `busy_timeout` must be set before `journal_mode=WAL`.
#: Converting the journal mode needs a brief exclusive lock, and without a
#: timeout already in force a concurrent opener fails immediately with
#: "database is locked" instead of waiting.
SQLITE_PRAGMAS: tuple[str, ...] = (
    "PRAGMA busy_timeout=5000",
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA foreign_keys=ON",
)


class LedgerIntegrityError(RuntimeError):
    """Raised when the ledger hash chain or a revision read is not trustworthy."""


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _entity_projection(entity: dict[str, Any]) -> dict[str, Any]:
    """Normalises one entity, defaulting exactly as the protocol specifies."""
    return {
        "logical_id": entity["logical_id"],
        "entity_type": entity.get("type", "FUNCTION"),
        "name": entity.get("name", entity["logical_id"]),
        "file_path": entity.get("file_path", "module.py"),
        "line_start": entity.get("line_start", 1),
        "line_end": entity.get("line_end", 10),
        "source_hash": entity.get(
            "source_hash", compute_sha256(entity["logical_id"])
        ),
    }


def _edge_projection(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "src": edge["src"],
        "dst": edge["dst"],
        "edge_type": edge.get("type", "CALLS"),
    }


def revision_canonical_hash(
    *,
    revision_id: str,
    repository_id: str,
    commit_id: str,
    parent_revision_id: str | None,
    branch: str,
    entities: Iterable[dict[str, Any]],
    edges: Iterable[dict[str, Any]],
) -> str:
    """SHA-256 over the canonical projection of one revision."""
    data = {
        "revision_id": revision_id,
        "repository_id": repository_id,
        "commit_id": commit_id,
        "parent_revision_id": parent_revision_id,
        "branch": branch,
        "entities": sorted(
            (_entity_projection(e) for e in entities), key=lambda x: x["logical_id"]
        ),
        "edges": sorted(
            (_edge_projection(e) for e in edges),
            key=lambda x: (x["src"], x["dst"], x["edge_type"]),
        ),
    }
    return compute_sha256(canonical_json(data))


def store_canonical_hash(
    revisions: Iterable[dict[str, Any]], event_hashes: Iterable[str]
) -> str:
    """SHA-256 over the whole store: every revision hash plus the event chain."""
    state = {
        "revisions": sorted(
            (
                {
                    "id": r["revision_id"],
                    "branch": r["branch"],
                    "commit_id": r["commit_id"],
                    "hash": r["canonical_hash"],
                }
                for r in revisions
            ),
            key=lambda x: x["id"],
        ),
        "events": list(event_hashes),
    }
    return compute_sha256(canonical_json(state))


class RevisionStore:
    """SQLite-backed revision + ledger store safe for concurrent processes."""

    def __init__(self, path: str, *, connect_attempts: int = 12) -> None:
        self.path = path
        self._conn = self._open(connect_attempts)

    def _open(self, attempts: int) -> sqlite3.Connection:
        """Opens the ledger, retrying transient lock contention.

        Converting the journal to WAL and creating the schema both need a brief
        exclusive lock. Under genuine multi-process contention SQLite can report
        SQLITE_BUSY even with a busy timeout, so acquisition is retried with
        backoff. An exhausted retry budget is a real lock-exhaustion condition
        and is raised as such rather than swallowed.
        """
        last: Exception | None = None
        for attempt in range(max(1, attempts)):
            conn = sqlite3.connect(
                self.path, check_same_thread=False, isolation_level=None, timeout=5.0
            )
            try:
                for pragma in SQLITE_PRAGMAS:
                    conn.execute(pragma)
                self._initialise(conn)
                return conn
            except sqlite3.OperationalError as exc:
                last = exc
                try:
                    conn.close()
                except Exception:
                    pass
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                time.sleep(0.05 * (attempt + 1))
        raise LedgerIntegrityError(
            f"could not acquire ledger {self.path} after {attempts} attempts: {last}"
        )

    def _initialise(self, conn: sqlite3.Connection) -> None:
        """Creates the schema on the caller's connection."""
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS revisions (
                revision_id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                commit_id TEXT NOT NULL,
                parent_revision_id TEXT,
                branch TEXT NOT NULL,
                canonical_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entities (
                revision_id TEXT NOT NULL,
                logical_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (revision_id, logical_id)
            );
            CREATE TABLE IF NOT EXISTS edges (
                revision_id TEXT NOT NULL,
                src TEXT NOT NULL,
                dst TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                PRIMARY KEY (revision_id, src, dst, edge_type)
            );
            CREATE TABLE IF NOT EXISTS branch_heads (
                branch TEXT PRIMARY KEY,
                latest_revision_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                prev_event_hash TEXT,
                event_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                detail TEXT
            );
            """
        )

    # ---- writes ---------------------------------------------------------
    def ingest_revision(
        self,
        *,
        revision_id: str,
        repository_id: str,
        commit_id: str,
        parent_revision_id: str | None,
        branch: str,
        entities: list[dict[str, Any]] | None = None,
        edges: list[dict[str, Any]] | None = None,
    ) -> str:
        """Atomically writes a revision and advances its branch head."""
        entities = entities or []
        edges = edges or []
        digest = revision_canonical_hash(
            revision_id=revision_id,
            repository_id=repository_id,
            commit_id=commit_id,
            parent_revision_id=parent_revision_id,
            branch=branch,
            entities=entities,
            edges=edges,
        )
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        try:
            for pragma in SQLITE_PRAGMAS:
                conn.execute(pragma)
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT OR REPLACE INTO revisions (revision_id, repository_id, "
                "commit_id, parent_revision_id, branch, canonical_hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (revision_id, repository_id, commit_id, parent_revision_id, branch, digest),
            )
            conn.execute("DELETE FROM entities WHERE revision_id = ?", (revision_id,))
            conn.executemany(
                "INSERT OR REPLACE INTO entities (revision_id, logical_id, payload) "
                "VALUES (?, ?, ?)",
                [
                    (revision_id, _entity_projection(e)["logical_id"],
                     canonical_json(_entity_projection(e)))
                    for e in entities
                ],
            )
            conn.execute("DELETE FROM edges WHERE revision_id = ?", (revision_id,))
            conn.executemany(
                "INSERT OR REPLACE INTO edges (revision_id, src, dst, edge_type) "
                "VALUES (?, ?, ?, ?)",
                [
                    (revision_id, _edge_projection(e)["src"],
                     _edge_projection(e)["dst"], _edge_projection(e)["edge_type"])
                    for e in edges
                ],
            )
            conn.execute(
                "INSERT OR REPLACE INTO branch_heads (branch, latest_revision_id) "
                "VALUES (?, ?)",
                (branch, revision_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return digest

    def append_event(
        self, event_id: str, event_type: str, payload: dict[str, Any]
    ) -> str:
        """Appends to the hash-chained ledger and returns the new event hash."""
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        try:
            for pragma in SQLITE_PRAGMAS:
                conn.execute(pragma)
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT event_hash FROM ledger_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev = row[0] if row else None
            body = {
                "id": event_id,
                "type": event_type,
                "payload": payload,
                "prev_event_hash": prev,
            }
            digest = compute_sha256(canonical_json(body))
            conn.execute(
                "INSERT INTO ledger_events (event_id, event_type, payload, "
                "prev_event_hash, event_hash) VALUES (?, ?, ?, ?, ?)",
                (event_id, event_type, canonical_json(payload), prev, digest),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return digest

    def record_anomaly(self, kind: str, detail: str = "") -> None:
        """Records a fail-closed condition observed by a worker."""
        conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        try:
            conn.execute(
                "INSERT INTO anomalies (kind, detail) VALUES (?, ?)", (kind, detail)
            )
        finally:
            conn.close()

    # ---- reads ----------------------------------------------------------
    def branch_state(self, branch: str) -> dict[str, Any]:
        """Latest revision on `branch` with its canonical hash and counts."""
        row = self._conn.execute(
            "SELECT latest_revision_id FROM branch_heads WHERE branch = ?",
            (branch,),
        ).fetchone()
        if not row:
            return {
                "latest_revision_id": "",
                "entity_count": 0,
                "edge_count": 0,
                "canonical_hash": "",
            }
        revision_id = row[0]
        rev = self._conn.execute(
            "SELECT canonical_hash FROM revisions WHERE revision_id = ?",
            (revision_id,),
        ).fetchone()
        if rev is None:
            # A head pointer without its revision is a torn read.
            raise LedgerIntegrityError(
                f"branch {branch} head {revision_id} has no revision row"
            )
        entities = self._conn.execute(
            "SELECT COUNT(*) FROM entities WHERE revision_id = ?", (revision_id,)
        ).fetchone()[0]
        edges = self._conn.execute(
            "SELECT COUNT(*) FROM edges WHERE revision_id = ?", (revision_id,)
        ).fetchone()[0]
        return {
            "latest_revision_id": revision_id,
            "entity_count": entities,
            "edge_count": edges,
            "canonical_hash": rev[0],
        }

    def revision_ids(self) -> list[str]:
        return [
            r[0]
            for r in self._conn.execute(
                "SELECT revision_id FROM revisions ORDER BY revision_id"
            )
        ]

    def events(self) -> list[dict[str, Any]]:
        """Ledger events in append order, including the payload.

        The payload is required to re-derive each event hash; a projection
        without it can only check chain continuity, not event integrity.
        """
        return [
            {
                "event_id": r[0],
                "event_type": r[1],
                "payload": json.loads(r[4]) if r[4] else {},
                "prev_event_hash": r[2],
                "event_hash": r[3],
            }
            for r in self._conn.execute(
                "SELECT event_id, event_type, prev_event_hash, event_hash, payload "
                "FROM ledger_events ORDER BY seq"
            )
        ]

    def anomalies(self) -> list[tuple[str, str]]:
        return [
            (r[0], r[1] or "")
            for r in self._conn.execute("SELECT kind, detail FROM anomalies")
        ]

    def verify_ledger_chain(self) -> bool:
        """Re-derives the whole hash chain; a break is an integrity failure.

        Each event hash is recomputed from its own id, type, payload and the
        predecessor's hash. A structurally linked chain with a tampered payload
        fails here, which a linkage-only check would miss.
        """
        prev: str | None = None
        for event in self.events():
            if event["prev_event_hash"] != prev:
                return False
            body = {
                "id": event["event_id"],
                "type": event["event_type"],
                "payload": event["payload"],
                "prev_event_hash": prev,
            }
            if compute_sha256(canonical_json(body)) != event["event_hash"]:
                return False
            prev = event["event_hash"]
        return True

    def canonical_store_hash(self) -> str:
        revisions = [
            {
                "revision_id": r[0],
                "branch": r[1],
                "commit_id": r[2],
                "canonical_hash": r[3],
            }
            for r in self._conn.execute(
                "SELECT revision_id, branch, commit_id, canonical_hash FROM revisions"
            )
        ]
        return store_canonical_hash(
            revisions, [e["event_hash"] for e in self.events()]
        )

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass