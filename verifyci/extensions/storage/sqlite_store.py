"""SQLite and In-Memory GraphStore implementation of GraphStoreProtocol."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping, Sequence

from verifyci.extensions.protocols import GraphEdge, GraphNode, GraphStoreProtocol


class SQLiteGraphStore(GraphStoreProtocol):
    """Zero-dependency, ACID-compliant CPG graph store backed by SQLite."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cpg_nodes (
                    commit_sha TEXT NOT NULL,
                    node_uid TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    symbol_name TEXT NOT NULL,
                    start_line INTEGER NOT NULL,
                    end_line INTEGER NOT NULL,
                    properties_json TEXT NOT NULL,
                    PRIMARY KEY (commit_sha, node_uid)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cpg_edges (
                    commit_sha TEXT NOT NULL,
                    edge_uid TEXT NOT NULL,
                    src_node_uid TEXT NOT NULL,
                    dst_node_uid TEXT NOT NULL,
                    edge_kind TEXT NOT NULL,
                    properties_json TEXT NOT NULL,
                    PRIMARY KEY (commit_sha, edge_uid)
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cpg_nodes_commit ON cpg_nodes (commit_sha)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cpg_edges_commit ON cpg_edges (commit_sha)"
            )

    def record_commit_snapshot(
        self,
        commit_sha: str,
        nodes: Sequence[GraphNode],
        edges: Sequence[GraphEdge],
    ) -> None:
        """Atomically record nodes and edges for a commit snapshot."""
        with self._conn:
            # Overwrite if snapshot already exists for this commit
            self._conn.execute("DELETE FROM cpg_nodes WHERE commit_sha = ?", (commit_sha,))
            self._conn.execute("DELETE FROM cpg_edges WHERE commit_sha = ?", (commit_sha,))

            node_rows = [
                (
                    commit_sha,
                    n.node_uid,
                    n.node_kind,
                    n.file_path,
                    n.symbol_name,
                    n.start_line,
                    n.end_line,
                    json.dumps(dict(n.properties)),
                )
                for n in nodes
            ]
            self._conn.executemany(
                """
                INSERT INTO cpg_nodes (
                    commit_sha, node_uid, node_kind, file_path,
                    symbol_name, start_line, end_line, properties_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                node_rows,
            )

            edge_rows = [
                (
                    commit_sha,
                    e.edge_uid,
                    e.src_node_uid,
                    e.dst_node_uid,
                    e.edge_kind,
                    json.dumps(dict(e.properties)),
                )
                for e in edges
            ]
            self._conn.executemany(
                """
                INSERT INTO cpg_edges (
                    commit_sha, edge_uid, src_node_uid, dst_node_uid,
                    edge_kind, properties_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                edge_rows,
            )

    def get_nodes_as_of(self, commit_sha: str) -> list[GraphNode]:
        """Query nodes active in the given commit snapshot."""
        cursor = self._conn.execute(
            """
            SELECT node_uid, node_kind, file_path, symbol_name, start_line, end_line, properties_json
            FROM cpg_nodes WHERE commit_sha = ?
            ORDER BY file_path, start_line, node_uid
            """,
            (commit_sha,),
        )
        nodes: list[GraphNode] = []
        for row in cursor.fetchall():
            props = json.loads(row["properties_json"]) if row["properties_json"] else {}
            nodes.append(
                GraphNode(
                    node_uid=row["node_uid"],
                    node_kind=row["node_kind"],
                    file_path=row["file_path"],
                    symbol_name=row["symbol_name"],
                    start_line=row["start_line"],
                    end_line=row["end_line"],
                    properties=props,
                )
            )
        return nodes

    def get_edges_as_of(self, commit_sha: str) -> list[GraphEdge]:
        """Query edges active in the given commit snapshot."""
        cursor = self._conn.execute(
            """
            SELECT edge_uid, src_node_uid, dst_node_uid, edge_kind, properties_json
            FROM cpg_edges WHERE commit_sha = ?
            ORDER BY edge_uid
            """,
            (commit_sha,),
        )
        edges: list[GraphEdge] = []
        for row in cursor.fetchall():
            props = json.loads(row["properties_json"]) if row["properties_json"] else {}
            edges.append(
                GraphEdge(
                    edge_uid=row["edge_uid"],
                    src_node_uid=row["src_node_uid"],
                    dst_node_uid=row["dst_node_uid"],
                    edge_kind=row["edge_kind"],
                    properties=props,
                )
            )
        return edges

    def close(self) -> None:
        self._conn.close()
