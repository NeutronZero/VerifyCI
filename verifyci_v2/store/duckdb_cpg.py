from __future__ import annotations

import json
import sqlite3
import time
from typing import Iterable, Literal, Sequence
import zlib

from verifyci_v2.contracts.canonical import canonical_jcs_bytes
from verifyci_v2.contracts.ssa_ir import (
    CPGEdge,
    FunctionUSSA,
    PhiNode,
    TaintSummary,
    USSABasicBlock,
    USSAInstruction,
)

try:
    import duckdb as _duckdb_mod  # type: ignore[import-untyped]
except ImportError:
    _duckdb_mod = None


def _compress_ussa(func: FunctionUSSA) -> bytes:
    return zlib.compress(canonical_jcs_bytes(func), level=6)


def _decompress_ussa(blob: bytes) -> FunctionUSSA:
    raw = json.loads(zlib.decompress(blob).decode("utf-8"))
    blocks = tuple(
        USSABasicBlock(
            block_id=b["block_id"],
            phi_nodes=tuple(
                PhiNode(
                    target_var=p["target_var"],
                    incoming_branches=tuple((br[0], br[1]) for br in p["incoming_branches"]),
                )
                for p in b["phi_nodes"]
            ),
            instructions=tuple(
                USSAInstruction(
                    inst_id=i["inst_id"],
                    opcode=i["opcode"],
                    target_var=i["target_var"],
                    operands=tuple(i["operands"]),
                    callee_symbol=i.get("callee_symbol"),
                    source_line=i.get("source_line", 0),
                )
                for i in b["instructions"]
            ),
            terminator_condition=b.get("terminator_condition"),
        )
        for b in raw["basic_blocks"]
    )
    cfg_edges = tuple(CPGEdge(**e) for e in raw["cfg_edges"])
    dfg_edges = tuple(CPGEdge(**e) for e in raw["dfg_edges"])
    ts = raw["taint_summary"]
    taint = TaintSummary(
        param_to_return=tuple(ts["param_to_return"]),
        param_to_sinks=tuple((pair[0], pair[1]) for pair in ts["param_to_sinks"]),
        mutated_globals=tuple(ts["mutated_globals"]),
        raised_exceptions=tuple(ts["raised_exceptions"]),
        is_pure=bool(ts["is_pure"]),
    )
    return FunctionUSSA(
        node_uid=raw["node_uid"],
        repo_id=raw["repo_id"],
        qualified_name=raw["qualified_name"],
        file_path=raw["file_path"],
        language=raw["language"],
        start_line=int(raw["start_line"]),
        end_line=int(raw["end_line"]),
        canonical_signature=raw["canonical_signature"],
        parameters=tuple(raw["parameters"]),
        return_annotation=raw["return_annotation"],
        basic_blocks=blocks,
        cfg_edges=cfg_edges,
        dfg_edges=dfg_edges,
        call_targets=tuple(raw["call_targets"]),
        taint_summary=taint,
        h_body=raw["h_body"],
        h_interface=raw["h_interface"],
    )


class DuckDBCPGStore:
    """
    Layer 4 Unified Relational Code Property Graph Store (`.verifyci/store.vc2`).
    Supports temporal commit snapshot isolation (`cap006` `AS OF` queries), CAS deduplication
    of FunctionUSSA nodes across commits, and coverage-weighted CPG edges.
    Uses DuckDB when installed, with a bit-for-bit compatible relational SQLite backend.
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        backend: Literal["auto", "duckdb", "sqlite"] = "auto",
    ) -> None:
        self.db_path = db_path
        if backend == "duckdb":
            if _duckdb_mod is None:
                raise RuntimeError("duckdb is requested but duckdb package is not installed")
            self._use_duckdb = True
            self.active_backend = "duckdb"
        elif backend == "sqlite":
            self._use_duckdb = False
            self.active_backend = "sqlite"
        else:
            self._use_duckdb = _duckdb_mod is not None and db_path.endswith(".vc2")
            self.active_backend = "duckdb" if self._use_duckdb else "sqlite"

        if self._use_duckdb:
            self._conn = _duckdb_mod.connect(db_path)
        else:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS commits (
                commit_sha TEXT PRIMARY KEY,
                parent_sha TEXT,
                rsl_entry_hash TEXT NOT NULL,
                ingested_at_epoch BIGINT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS function_nodes (
                node_uid TEXT PRIMARY KEY,
                qualified_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                language TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                h_interface TEXT NOT NULL,
                h_body TEXT NOT NULL,
                ussa_payload BLOB NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS commit_node_map (
                commit_sha TEXT NOT NULL,
                node_uid TEXT NOT NULL,
                PRIMARY KEY (commit_sha, node_uid)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cpg_edges (
                edge_key TEXT PRIMARY KEY,
                edge_uid TEXT NOT NULL,
                src_node_uid TEXT NOT NULL,
                dst_node_uid TEXT NOT NULL,
                edge_kind TEXT NOT NULL,
                predicate_label TEXT,
                static_weight DOUBLE DEFAULT 1.0,
                coverage_hit_freq DOUBLE DEFAULT 0.0
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS commit_edge_map (
                commit_sha TEXT NOT NULL,
                edge_key TEXT NOT NULL,
                PRIMARY KEY (commit_sha, edge_key)
            )
            """
        )
        self._conn.commit()

    def record_commit_snapshot(
        self,
        commit_sha: str,
        functions: Sequence[FunctionUSSA],
        edges: Sequence[CPGEdge] = (),
        *,
        parent_sha: str | None = None,
        rsl_entry_hash: str = "genesis",
        timestamp_epoch: int | None = None,
    ) -> int:
        ts = timestamp_epoch if timestamp_epoch is not None else int(time.time())
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO commits (commit_sha, parent_sha, rsl_entry_hash, ingested_at_epoch)
            VALUES (?, ?, ?, ?)
            """,
            (commit_sha, parent_sha, rsl_entry_hash, ts),
        )

        # Replacement semantics: clear stale commit mappings if re-recording the same commit
        cur.execute("DELETE FROM commit_node_map WHERE commit_sha = ?", (commit_sha,))
        cur.execute("DELETE FROM commit_edge_map WHERE commit_sha = ?", (commit_sha,))

        for fn in functions:
            payload = _compress_ussa(fn)
            cur.execute(
                """
                INSERT OR REPLACE INTO function_nodes
                (node_uid, qualified_name, file_path, language, start_line, end_line, h_interface, h_body, ussa_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fn.node_uid,
                    fn.qualified_name,
                    fn.file_path,
                    fn.language,
                    fn.start_line,
                    fn.end_line,
                    fn.h_interface,
                    fn.h_body,
                    payload,
                ),
            )
            cur.execute(
                """
                INSERT OR REPLACE INTO commit_node_map (commit_sha, node_uid)
                VALUES (?, ?)
                """,
                (commit_sha, fn.node_uid),
            )
            for edge in (*fn.cfg_edges, *fn.dfg_edges):
                edge_key = self._upsert_edge(cur, edge)
                cur.execute(
                    """
                    INSERT OR REPLACE INTO commit_edge_map (commit_sha, edge_key)
                    VALUES (?, ?)
                    """,
                    (commit_sha, edge_key),
                )

        for edge in edges:
            edge_key = self._upsert_edge(cur, edge)
            cur.execute(
                """
                INSERT OR REPLACE INTO commit_edge_map (commit_sha, edge_key)
                VALUES (?, ?)
                """,
                (commit_sha, edge_key),
            )

        self._conn.commit()
        return len(functions)

    def get_edges_as_of(self, commit_sha: str) -> tuple[CPGEdge, ...]:
        """Retrieves the exact set of CPGEdge items active at `commit_sha` via commit_edge_map."""
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT e.edge_uid, e.src_node_uid, e.dst_node_uid, e.edge_kind, e.predicate_label, e.static_weight, e.coverage_hit_freq
            FROM cpg_edges e
            INNER JOIN commit_edge_map cem ON e.edge_key = cem.edge_key
            WHERE cem.commit_sha = ?
            ORDER BY e.edge_uid ASC
            """,
            (commit_sha,),
        )
        rows = cur.fetchall()
        return tuple(
            CPGEdge(
                edge_uid=r[0],
                src_node_uid=r[1],
                dst_node_uid=r[2],
                edge_kind=r[3],
                predicate_label=r[4],
                static_weight=float(r[5]),
                coverage_hit_freq=float(r[6]),
            )
            for r in rows
        )

    def _upsert_edge(self, cur: sqlite3.Cursor, edge: CPGEdge) -> str:
        edge_key = f"{edge.edge_uid}::{edge.static_weight}::{edge.coverage_hit_freq}::{edge.predicate_label}"
        cur.execute(
            """
            INSERT OR REPLACE INTO cpg_edges
            (edge_key, edge_uid, src_node_uid, dst_node_uid, edge_kind, predicate_label, static_weight, coverage_hit_freq)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                edge_key,
                edge.edge_uid,
                edge.src_node_uid,
                edge.dst_node_uid,
                edge.edge_kind,
                edge.predicate_label,
                edge.static_weight,
                edge.coverage_hit_freq,
            ),
        )
        return edge_key

    def get_functions_as_of(self, commit_sha: str) -> tuple[FunctionUSSA, ...]:
        """Retrieves the exact set of FunctionUSSA nodes active at `commit_sha` (`cap006`)."""
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT fn.ussa_payload
            FROM function_nodes fn
            INNER JOIN commit_node_map cnm ON fn.node_uid = cnm.node_uid
            WHERE cnm.commit_sha = ?
            ORDER BY fn.qualified_name ASC
            """,
            (commit_sha,),
        )
        rows = cur.fetchall()
        return tuple(_decompress_ussa(bytes(r[0])) for r in rows)

    def get_function_as_of(self, commit_sha: str, qualified_name: str) -> FunctionUSSA | None:
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT fn.ussa_payload
            FROM function_nodes fn
            INNER JOIN commit_node_map cnm ON fn.node_uid = cnm.node_uid
            WHERE cnm.commit_sha = ? AND fn.qualified_name = ?
            LIMIT 1
            """,
            (commit_sha, qualified_name),
        )
        row = cur.fetchone()
        return _decompress_ussa(bytes(row[0])) if row is not None else None

    def apply_coverage_weights(self, coverage_by_qname: dict[str, float]) -> int:
        """Updates CPG edges with dynamic line/function execution frequencies from pytest-cov."""
        cur = self._conn.cursor()
        updated = 0
        for qname, freq in coverage_by_qname.items():
            cur.execute(
                """
                UPDATE cpg_edges
                SET coverage_hit_freq = ?, static_weight = 1.0 + ?
                WHERE src_node_uid = ? OR dst_node_uid = ?
                """,
                (freq, freq, qname, qname),
            )
            updated += cur.rowcount
        self._conn.commit()
        return updated

    def select_prioritized_tests(
        self,
        affected_qnames: Iterable[str],
    ) -> dict[str, tuple[str, ...]]:
        """Categorizes affected test functions into Tier 1 (Coverage-Hit) and Tier 2 (Static-Only)."""
        cur = self._conn.cursor()
        tier1: set[str] = set()
        tier2: set[str] = set()
        for qn in affected_qnames:
            if "test_" in qn or ".tests." in qn:
                cur.execute(
                    "SELECT MAX(coverage_hit_freq) FROM cpg_edges WHERE src_node_uid = ? OR dst_node_uid = ?",
                    (qn, qn),
                )
                row = cur.fetchone()
                freq = float(row[0]) if row and row[0] is not None else 0.0
                if freq > 0.0:
                    tier1.add(qn)
                else:
                    tier2.add(qn)
        return {
            "tier1_dynamically_executed": tuple(sorted(tier1)),
            "tier2_statically_reached": tuple(sorted(tier2)),
        }