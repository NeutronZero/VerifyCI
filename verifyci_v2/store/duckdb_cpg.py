from __future__ import annotations

import json
import math
import sqlite3
import struct
import time
import zlib
from typing import Iterable, Literal, Sequence

import msgspec

from verifyci_v2.contracts.canonical import blake3_hex, canonical_jcs_bytes
from verifyci_v2.contracts.ssa_ir import (
    CPGEdge,
    FunctionUSSA,
)

try:
    import duckdb as _duckdb_mod  # type: ignore[import-untyped]
except ImportError:
    _duckdb_mod = None


def _compress_ussa(func: FunctionUSSA) -> bytes:
    return zlib.compress(canonical_jcs_bytes(func), level=6)


def _decompress_ussa(blob: bytes) -> FunctionUSSA:
    return msgspec.json.decode(zlib.decompress(blob), type=FunctionUSSA)


def _pack_rabitq_bits(vec: Sequence[float]) -> tuple[bytes, float, float]:
    """
    Quantizes a float vector into packed 64-bit unsigned words (RaBitQ sign bits),
    returning (packed_bytes, l2_norm, corrective_factor).
    """
    norm_sq = sum(x * x for x in vec)
    l2_norm = math.sqrt(norm_sq) if norm_sq > 1e-12 else 1.0
    dim = len(vec)
    inv_sqrt_d = 1.0 / math.sqrt(max(dim, 1))

    # Corrective scalar <o_bar, u> = sum(|u_i|) / sqrt(D)
    dot_o_u = sum(abs(x / l2_norm) for x in vec) * inv_sqrt_d
    corrective = max(dot_o_u, 1e-6)

    num_words = (dim + 63) // 64
    words = [0] * num_words
    for idx, val in enumerate(vec):
        if val >= 0.0:
            words[idx // 64] |= 1 << (idx % 64)

    packed = struct.pack(f"<{num_words}Q", *words)
    return packed, l2_norm, corrective


def _hamming_distance_bytes(a: bytes, b: bytes) -> int:
    """Fast bitwise popcount over packed 64-bit words."""
    n = min(len(a), len(b)) // 8
    wa = struct.unpack(f"<{n}Q", a[: n * 8])
    wb = struct.unpack(f"<{n}Q", b[: n * 8])
    return sum((x ^ y).bit_count() for x, y in zip(wa, wb))


_SQLITE_MAGIC = b"SQLite format 3\x00"


def _read_file_magic(path: str, length: int = 16) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(length)
    except OSError:
        return b""


class DuckDBCPGStore:
    """
    Layer 4 Unified Relational Code Property Graph + RaBitQ Vector Store (`.verifyci/store.vc2`).
    Provides:
      - Content-Addressed Storage (CAS) for FunctionUSSA nodes and relational EDB facts
      - Temporal commit snapshot isolation (`AS OF` queries)
      - Stratified Recursive CTEs for Blast Radius and Interprocedural Taint Reachability
      - Embedded RaBitQ error-bounded bit-vector indexing
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        backend: Literal["auto", "duckdb", "sqlite"] = "auto",
    ) -> None:
        self.db_path = db_path
        if backend == "duckdb":
            if _duckdb_mod is None:
                raise RuntimeError(
                    "duckdb is requested but duckdb package is not installed"
                )
            self._use_duckdb = True
        elif backend == "sqlite":
            self._use_duckdb = False
        else:
            # Default to DuckDB whenever installed unless explicitly given a .sqlite/.db file
            is_sqlite_ext = db_path.endswith((".sqlite", ".sqlite3", ".db"))
            self._use_duckdb = _duckdb_mod is not None and not is_sqlite_ext

        self.active_backend = "duckdb" if self._use_duckdb else "sqlite"

        if self._use_duckdb:
            # Fail closed on a cross-format store: DuckDB auto-detects a SQLite
            # file and then fails deep inside DML with a confusing error, so the
            # mismatch is rejected here with an actionable message instead.
            if db_path != ":memory:":
                magic = _read_file_magic(db_path)
                if magic == _SQLITE_MAGIC:
                    raise RuntimeError(
                        f"Store '{db_path}' is a SQLite database but the duckdb backend "
                        "was selected. Re-ingest to a new path or pass --backend sqlite."
                    )
            self._conn = _duckdb_mod.connect(db_path, config={"threads": "1"})
        else:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS source_snapshots (
                commit_sha TEXT NOT NULL,
                file_path TEXT NOT NULL,
                source_text TEXT NOT NULL,
                PRIMARY KEY (commit_sha, file_path)
            );
            """
        )
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
                canonical_signature TEXT DEFAULT '',
                is_pure BOOLEAN DEFAULT FALSE,
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
            CREATE TABLE IF NOT EXISTS cpg_blocks (
                node_uid TEXT NOT NULL,
                block_id TEXT NOT NULL,
                terminator_condition TEXT,
                phi_json TEXT NOT NULL,
                PRIMARY KEY (node_uid, block_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cpg_instructions (
                node_uid TEXT NOT NULL,
                block_id TEXT NOT NULL,
                inst_id TEXT NOT NULL,
                opcode TEXT NOT NULL,
                target_var TEXT,
                operands_json TEXT NOT NULL,
                callee_symbol TEXT,
                source_line INTEGER NOT NULL,
                PRIMARY KEY (node_uid, inst_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cpg_taint_summaries (
                node_uid TEXT PRIMARY KEY,
                qualified_name TEXT NOT NULL,
                is_pure BOOLEAN NOT NULL,
                param_to_return_json TEXT NOT NULL,
                param_to_sinks_json TEXT NOT NULL,
                mutated_globals_json TEXT NOT NULL,
                raised_exceptions_json TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS cpg_edges (
                edge_key TEXT PRIMARY KEY,
                edge_uid TEXT NOT NULL,
                owner_node_uid TEXT DEFAULT '',
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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS rabitq_embeddings (
                node_uid TEXT PRIMARY KEY,
                qualified_name TEXT NOT NULL,
                dim INTEGER NOT NULL,
                packed_bits BLOB NOT NULL,
                l2_norm DOUBLE NOT NULL,
                corrective_factor DOUBLE NOT NULL
            )
            """
        )
        self._conn.commit()

    def record_source_snapshot(
        self, commit_sha: str, sources: dict[str, str]
    ) -> int:
        """Stores verbatim source per file for a commit.

        Removal provenance needs the *base revision text*, not a derived U-SSA
        payload: `function_nodes.ussa_payload` holds compressed IR, so a stored
        record can never contradict a diff that claims to delete code. This
        table is the only place that keeps the original text.
        """
        cur = self._conn.cursor()
        rows = [
            (commit_sha, file_path, source)
            for file_path, source in sources.items()
            if source
        ]
        cur.executemany(
            "INSERT OR REPLACE INTO source_snapshots "
            "(commit_sha, file_path, source_text) VALUES (?, ?, ?)",
            rows,
        )
        self._conn.commit()
        return len(rows)

    def load_source_snapshot(self, commit_sha: str) -> dict[str, str]:
        """Returns the stored verbatim source for a commit, keyed by path."""
        cur = self._conn.cursor()
        try:
            cur.execute(
                "SELECT file_path, source_text FROM source_snapshots "
                "WHERE commit_sha = ?",
                (commit_sha,),
            )
            return {str(row[0]): str(row[1]) for row in cur.fetchall()}
        except Exception:
            # A store written before this table exists simply has no
            # provenance; that is an absence, not a failure.
            return {}

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

        cur.execute("DELETE FROM commit_node_map WHERE commit_sha = ?", (commit_sha,))
        cur.execute("DELETE FROM commit_edge_map WHERE commit_sha = ?", (commit_sha,))

        qname_lookup = {
            fn.qualified_name.split(".")[-1]: fn.qualified_name for fn in functions
        }
        fn_rows: list[tuple] = []
        commit_node_rows: list[tuple] = []
        taint_rows: list[tuple] = []
        block_rows: list[tuple] = []
        inst_rows: list[tuple] = []
        edge_map_to_upsert: dict[str, tuple] = {}
        commit_edge_rows: list[tuple] = []

        for fn in functions:
            payload = _compress_ussa(fn)
            fn_rows.append(
                (
                    fn.node_uid,
                    fn.qualified_name,
                    fn.file_path,
                    fn.language,
                    fn.start_line,
                    fn.end_line,
                    fn.canonical_signature,
                    fn.taint_summary.is_pure,
                    fn.h_interface,
                    fn.h_body,
                    payload,
                )
            )
            commit_node_rows.append((commit_sha, fn.node_uid))
            taint_rows.append(
                (
                    fn.node_uid,
                    fn.qualified_name,
                    fn.taint_summary.is_pure,
                    json.dumps(fn.taint_summary.param_to_return),
                    json.dumps(fn.taint_summary.param_to_sinks),
                    json.dumps(fn.taint_summary.mutated_globals),
                    json.dumps(fn.taint_summary.raised_exceptions),
                )
            )

            for blk in fn.basic_blocks:
                phi_data = [
                    {"target_var": p.target_var, "incoming": list(p.incoming_branches)}
                    for p in blk.phi_nodes
                ]
                block_rows.append(
                    (
                        fn.node_uid,
                        blk.block_id,
                        blk.terminator_condition,
                        json.dumps(phi_data),
                    )
                )
                for inst in blk.instructions:
                    inst_rows.append(
                        (
                            fn.node_uid,
                            blk.block_id,
                            inst.inst_id,
                            inst.opcode,
                            inst.target_var,
                            json.dumps(inst.operands),
                            inst.callee_symbol,
                            inst.source_line,
                        )
                    )

            for edge in (*fn.cfg_edges, *fn.dfg_edges):
                k = (
                    f"{fn.node_uid}::{edge.edge_uid}::{edge.static_weight}"
                    f"::{edge.coverage_hit_freq}::{edge.predicate_label}"
                )
                edge_map_to_upsert[k] = (
                    k,
                    edge.edge_uid,
                    fn.node_uid,
                    edge.src_node_uid,
                    edge.dst_node_uid,
                    edge.edge_kind,
                    edge.predicate_label,
                    edge.static_weight,
                    edge.coverage_hit_freq,
                )
                commit_edge_rows.append((commit_sha, k))

            for target in fn.call_targets:
                resolved_dst = qname_lookup.get(target, target)
                call_uid = blake3_hex(
                    f"{fn.qualified_name}:CALL:{resolved_dst}",
                    domain="verifyci.v2.call_edge",
                )[:24]
                k = f"{fn.node_uid}::{call_uid}::1.0::0.0::None"
                edge_map_to_upsert[k] = (
                    k,
                    call_uid,
                    fn.node_uid,
                    fn.qualified_name,
                    resolved_dst,
                    "CALL",
                    None,
                    1.0,
                    0.0,
                )
                commit_edge_rows.append((commit_sha, k))

        for edge in edges:
            k = f"::{edge.edge_uid}::{edge.static_weight}::{edge.coverage_hit_freq}::{edge.predicate_label}"
            edge_map_to_upsert[k] = (
                k,
                edge.edge_uid,
                "",
                edge.src_node_uid,
                edge.dst_node_uid,
                edge.edge_kind,
                edge.predicate_label,
                edge.static_weight,
                edge.coverage_hit_freq,
            )
            commit_edge_rows.append((commit_sha, k))

        if fn_rows:
            cur.executemany(
                """
                INSERT OR REPLACE INTO function_nodes
                (node_uid, qualified_name, file_path, language, start_line, end_line,
                 canonical_signature, is_pure, h_interface, h_body, ussa_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                fn_rows,
            )
            cur.executemany(
                "INSERT OR REPLACE INTO commit_node_map (commit_sha, node_uid) VALUES (?, ?)",
                commit_node_rows,
            )
            cur.executemany(
                """
                INSERT OR REPLACE INTO cpg_taint_summaries
                (node_uid, qualified_name, is_pure, param_to_return_json, param_to_sinks_json,
                 mutated_globals_json, raised_exceptions_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                taint_rows,
            )
        if block_rows:
            cur.executemany(
                """
                INSERT OR REPLACE INTO cpg_blocks
                (node_uid, block_id, terminator_condition, phi_json)
                VALUES (?, ?, ?, ?)
                """,
                block_rows,
            )
        if inst_rows:
            cur.executemany(
                """
                INSERT OR REPLACE INTO cpg_instructions
                (node_uid, block_id, inst_id, opcode, target_var, operands_json, callee_symbol, source_line)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                inst_rows,
            )
        if edge_map_to_upsert:
            cur.executemany(
                """
                INSERT OR REPLACE INTO cpg_edges
                (edge_key, edge_uid, owner_node_uid, src_node_uid, dst_node_uid,
                 edge_kind, predicate_label, static_weight, coverage_hit_freq)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                list(edge_map_to_upsert.values()),
            )
        if commit_edge_rows:
            cur.executemany(
                """
                INSERT OR REPLACE INTO commit_edge_map (commit_sha, edge_key)
                VALUES (?, ?)
                """,
                commit_edge_rows,
            )

        self._conn.commit()
        return len(functions)

    def _upsert_edge(
        self,
        cur: sqlite3.Cursor,
        edge: CPGEdge,
        owner_node_uid: str = "",
    ) -> str:
        edge_key = (
            f"{owner_node_uid}::{edge.edge_uid}::{edge.static_weight}"
            f"::{edge.coverage_hit_freq}::{edge.predicate_label}"
        )
        cur.execute(
            """
            INSERT OR REPLACE INTO cpg_edges
            (edge_key, edge_uid, owner_node_uid, src_node_uid, dst_node_uid,
             edge_kind, predicate_label, static_weight, coverage_hit_freq)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                edge_key,
                edge.edge_uid,
                owner_node_uid,
                edge.src_node_uid,
                edge.dst_node_uid,
                edge.edge_kind,
                edge.predicate_label,
                edge.static_weight,
                edge.coverage_hit_freq,
            ),
        )
        return edge_key

    def get_edges_as_of(
        self,
        commit_sha: str,
        *,
        edge_kinds: Sequence[str] | None = None,
    ) -> tuple[CPGEdge, ...]:
        cur = self._conn.cursor()
        if edge_kinds:
            placeholders = ", ".join("?" for _ in edge_kinds)
            cur.execute(
                f"""
                SELECT e.edge_uid, e.src_node_uid, e.dst_node_uid, e.edge_kind,
                       e.predicate_label, e.static_weight, e.coverage_hit_freq
                FROM cpg_edges e
                INNER JOIN commit_edge_map cem ON e.edge_key = cem.edge_key
                WHERE cem.commit_sha = ? AND e.edge_kind IN ({placeholders})
                ORDER BY e.edge_uid ASC
                """,
                (commit_sha, *edge_kinds),
            )
        else:
            cur.execute(
                """
                SELECT e.edge_uid, e.src_node_uid, e.dst_node_uid, e.edge_kind,
                       e.predicate_label, e.static_weight, e.coverage_hit_freq
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

    def get_functions_as_of(self, commit_sha: str) -> tuple[FunctionUSSA, ...]:
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

    def get_function_as_of(
        self, commit_sha: str, qualified_name: str
    ) -> FunctionUSSA | None:
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
            updated += max(0, cur.rowcount)
        self._conn.commit()
        return updated

    def select_prioritized_tests(
        self,
        affected_qnames: Iterable[str],
    ) -> dict[str, tuple[str, ...]]:
        candidate_tests = [
            qn for qn in affected_qnames if "test_" in qn or ".tests." in qn
        ]
        if not candidate_tests:
            return {
                "tier1_dynamically_executed": (),
                "tier2_statically_reached": (),
            }

        cur = self._conn.cursor()
        tier1: set[str] = set()
        tier2: set[str] = set()
        placeholders = ", ".join("?" for _ in candidate_tests)
        cur.execute(
            f"""
            SELECT src_node_uid
            FROM cpg_edges
            WHERE src_node_uid IN ({placeholders}) AND coverage_hit_freq > 0.0
            UNION
            SELECT dst_node_uid
            FROM cpg_edges
            WHERE dst_node_uid IN ({placeholders}) AND coverage_hit_freq > 0.0
            """,
            (*candidate_tests, *candidate_tests),
        )
        tier1_set = {str(row[0]) for row in cur.fetchall()}
        for qn in candidate_tests:
            if qn in tier1_set:
                tier1.add(qn)
            else:
                tier2.add(qn)

        return {
            "tier1_dynamically_executed": tuple(sorted(tier1)),
            "tier2_statically_reached": tuple(sorted(tier2)),
        }

    # -------------------------------------------------------------------------
    # Stage-1 Relational Reachability Queries (Blast Radius & Taint Chains)
    # -------------------------------------------------------------------------
    def query_blast_radius_cte(
        self,
        commit_sha: str,
        seed_qnames: Sequence[str],
        *,
        max_hops: int = 5,
    ) -> tuple[tuple[str, int, float], ...]:
        """
        Computes reverse call/dependency reachability (callers impacted by seed_qnames)
        as a single recursive CTE at `commit_sha`.
        Returns sorted tuples of (impacted_qname, min_hop_distance, max_coverage_weight).
        """
        if not seed_qnames:
            return ()
        cur = self._conn.cursor()
        placeholders = ", ".join("?" for _ in seed_qnames)
        cur.execute(
            f"""
            WITH RECURSIVE active_edges AS (
                SELECT e.src_node_uid, e.dst_node_uid, e.static_weight
                FROM cpg_edges e
                INNER JOIN commit_edge_map cem ON e.edge_key = cem.edge_key
                WHERE cem.commit_sha = ?
                  AND e.edge_kind IN ('CALL', 'CALLS', 'IMPORT', 'FFI_BRIDGE')
            ),
            impact_walk(node_qname, hop, weight) AS (
                SELECT dst_node_uid, 0, 1.0
                FROM active_edges
                WHERE dst_node_uid IN ({placeholders})
                UNION
                SELECT ae.src_node_uid, iw.hop + 1, ae.static_weight
                FROM active_edges ae
                INNER JOIN impact_walk iw ON ae.dst_node_uid = iw.node_qname
                WHERE iw.hop < ?
            )
            SELECT node_qname, MIN(hop) AS min_hop, MAX(weight) AS max_w
            FROM impact_walk
            GROUP BY node_qname
            ORDER BY min_hop ASC, max_w DESC, node_qname ASC
            """,
            (commit_sha, *seed_qnames, max_hops),
        )
        return tuple((str(r[0]), int(r[1]), float(r[2])) for r in cur.fetchall())

    # -------------------------------------------------------------------------
    # Unified RaBitQ Bit-Vector Indexing & Error-Bounded Search
    # -------------------------------------------------------------------------
    def upsert_rabitq_embedding(
        self,
        node_uid: str,
        qualified_name: str,
        embedding: Sequence[float],
    ) -> None:
        packed, l2_norm, corrective = _pack_rabitq_bits(embedding)
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO rabitq_embeddings
            (node_uid, qualified_name, dim, packed_bits, l2_norm, corrective_factor)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (node_uid, qualified_name, len(embedding), packed, l2_norm, corrective),
        )
        self._conn.commit()

    def search_rabitq_as_of(
        self,
        commit_sha: str,
        query_embedding: Sequence[float],
        *,
        top_k: int = 10,
    ) -> tuple[tuple[str, str, float], ...]:
        """
        Executes commit-scoped RaBitQ similarity search over `rabitq_embeddings`
        joined against `commit_node_map`.
        Returns top_k tuples of (node_uid, qualified_name, estimated_cosine_score).
        """
        q_packed, _q_norm, q_corr = _pack_rabitq_bits(query_embedding)
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT r.node_uid, r.qualified_name, r.dim, r.packed_bits, r.corrective_factor
            FROM rabitq_embeddings r
            INNER JOIN commit_node_map cnm ON r.node_uid = cnm.node_uid
            WHERE cnm.commit_sha = ?
            """,
            (commit_sha,),
        )
        scored: list[tuple[str, str, float]] = []
        for node_uid, qname, dim, packed_blob, d_corr in cur.fetchall():
            d_bytes = bytes(packed_blob)
            hamming = _hamming_distance_bytes(q_packed, d_bytes)
            # RaBitQ inner-product estimator: (1 - 2 * H / D) / (corrective_d * corrective_q)
            raw_ip = 1.0 - (2.0 * float(hamming) / float(max(dim, 1)))
            denom = max(float(d_corr) * q_corr, 1e-6)
            est_cos = max(-1.0, min(1.0, raw_ip / denom))
            scored.append((str(node_uid), str(qname), round(est_cos, 6)))

        scored.sort(key=lambda item: (-item[2], item[1]))
        return tuple(scored[:top_k])
