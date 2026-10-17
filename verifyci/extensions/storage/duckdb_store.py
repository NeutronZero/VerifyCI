"""DuckDB GraphStore backend with temporal commit isolation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from verifyci.extensions.protocols import GraphEdge, GraphNode, GraphStoreProtocol


def _get_duckdb() -> Any:
    try:
        import duckdb
        return duckdb
    except ImportError:
        return None


class DuckDBGraphStore(GraphStoreProtocol):
    """High-performance analytical CPG store backed by DuckDB."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.duckdb = _get_duckdb()
        if self.duckdb is None:
            raise RuntimeError("DuckDB backend requested but 'duckdb' is not installed.")

        self.db_path = str(db_path)
        self._conn = self.duckdb.connect(self.db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cpg_nodes (
                commit_sha VARCHAR NOT NULL,
                node_uid VARCHAR NOT NULL,
                node_kind VARCHAR NOT NULL,
                file_path VARCHAR NOT NULL,
                symbol_name VARCHAR NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                properties_json VARCHAR NOT NULL,
                PRIMARY KEY (commit_sha, node_uid)
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cpg_edges (
                commit_sha VARCHAR NOT NULL,
                edge_uid VARCHAR NOT NULL,
                src_node_uid VARCHAR NOT NULL,
                dst_node_uid VARCHAR NOT NULL,
                edge_kind VARCHAR NOT NULL,
                properties_json VARCHAR NOT NULL,
                PRIMARY KEY (commit_sha, edge_uid)
            )
            """
        )

    def record_commit_snapshot(
        self,
        commit_sha: str,
        nodes: Sequence[GraphNode],
        edges: Sequence[GraphEdge],
    ) -> None:
        self._conn.execute("DELETE FROM cpg_nodes WHERE commit_sha = ?", [commit_sha])
        self._conn.execute("DELETE FROM cpg_edges WHERE commit_sha = ?", [commit_sha])

        if nodes:
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
                INSERT INTO cpg_nodes VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                node_rows,
            )

        if edges:
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
                INSERT INTO cpg_edges VALUES (?, ?, ?, ?, ?, ?)
                """,
                edge_rows,
            )

    def get_nodes_as_of(self, commit_sha: str) -> list[GraphNode]:
        res = self._conn.execute(
            """
            SELECT node_uid, node_kind, file_path, symbol_name, start_line, end_line, properties_json
            FROM cpg_nodes WHERE commit_sha = ?
            ORDER BY file_path, start_line, node_uid
            """,
            [commit_sha],
        ).fetchall()

        nodes: list[GraphNode] = []
        for row in res:
            props = json.loads(row[6]) if row[6] else {}
            nodes.append(
                GraphNode(
                    node_uid=row[0],
                    node_kind=row[1],
                    file_path=row[2],
                    symbol_name=row[3],
                    start_line=row[4],
                    end_line=row[5],
                    properties=props,
                )
            )
        return nodes

    def get_edges_as_of(self, commit_sha: str) -> list[GraphEdge]:
        res = self._conn.execute(
            """
            SELECT edge_uid, src_node_uid, dst_node_uid, edge_kind, properties_json
            FROM cpg_edges WHERE commit_sha = ?
            ORDER BY edge_uid
            """,
            [commit_sha],
        ).fetchall()

        edges: list[GraphEdge] = []
        for row in res:
            props = json.loads(row[4]) if row[4] else {}
            edges.append(
                GraphEdge(
                    edge_uid=row[0],
                    src_node_uid=row[1],
                    dst_node_uid=row[2],
                    edge_kind=row[3],
                    properties=props,
                )
            )
        return edges

    def close(self) -> None:
        self._conn.close()
