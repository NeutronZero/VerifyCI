from __future__ import annotations

import json
import math
import re
import sqlite3
import struct
import time
import zlib
import subprocess
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

import msgspec

from verifyci_v2.contracts.canonical import content_digest_hex, canonical_jcs_bytes, canonical_jcs_str
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
    """Canonical sign-bit packing with the store's existing correction math."""
    from verifyci_v2.store.rabitq_index import pack_rabitq_sign_bits

    dim = len(vec)
    if dim <= 0:
        raise ValueError("RaBitQ vector dimension must be >= 1")
    norm_sq = sum(x * x for x in vec)
    l2_norm = math.sqrt(norm_sq) if norm_sq > 1e-12 else 1.0
    inv_sqrt_d = 1.0 / math.sqrt(dim)
    # Preserve the existing persistence estimator; only packing is unified.
    dot_o_u = sum(abs(x / l2_norm) for x in vec) * inv_sqrt_d
    corrective = max(dot_o_u, 1e-6)
    packed, _packed_int = pack_rabitq_sign_bits(vec)
    return packed, l2_norm, corrective


def _hamming_distance_bytes(a: bytes, b: bytes) -> int:
    """Fast bitwise popcount over packed 64-bit words."""
    if not a or not b or len(a) != len(b) or len(a) % 8:
        raise ValueError("RaBitQ packed vectors must have equal non-zero 64-bit-aligned lengths")
    n = len(a) // 8
    wa = struct.unpack(f"<{n}Q", a)
    wb = struct.unpack(f"<{n}Q", b)
    return sum((x ^ y).bit_count() for x, y in zip(wa, wb))


_SQLITE_MAGIC = b"SQLite format 3\x00"


def _read_file_magic(path: str, length: int = 16) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(length)
    except OSError:
        return b""


class LineageIntegrityError(RuntimeError):
    """Raised when a persisted source snapshot does not match its manifest."""


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
        repo_path: str | Path | None = None,
        allow_unverified_snapshots: bool = False,
    ) -> None:
        self.db_path = db_path
        self.repo_path = Path(repo_path).resolve() if repo_path and (Path(repo_path) / ".git").exists() else None
        # Test-only escape hatch for exercising content-digest integrity without
        # an actual Git object database. Never enable this for a release/CI gate.
        self.allow_unverified_snapshots = allow_unverified_snapshots
        if backend == "duckdb":
            if _duckdb_mod is None:
                raise RuntimeError(
                    "duckdb is requested but duckdb package is not installed"
                )
            self._use_duckdb = True
        elif backend == "sqlite":
            self._use_duckdb = False
        else:
            # Prefer the existing file's magic over the filename extension. Older
            # local-first versions may have created a SQLite database at the
            # conventional `.verifyci/store.vc2` path before DuckDB was installed.
            is_sqlite_ext = db_path.endswith((".sqlite", ".sqlite3", ".db"))
            magic = _read_file_magic(db_path) if db_path != ":memory:" else b""
            if magic == _SQLITE_MAGIC or is_sqlite_ext:
                self._use_duckdb = False
            elif _duckdb_mod is not None:
                self._use_duckdb = True
            elif db_path != ":memory:" and Path(db_path).exists() and Path(db_path).stat().st_size > 0:
                raise RuntimeError(
                    f"Store '{db_path}' is not a SQLite database and DuckDB is unavailable; "
                    "install duckdb or provide the correct backend."
                )
            else:
                self._use_duckdb = False

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
            duckdb_io_error = getattr(_duckdb_mod, "IOException", Exception)
            try:
                self._conn = _duckdb_mod.connect(db_path, config={"threads": "1"})
            except duckdb_io_error as exc:
                if "used by another process" in str(exc) or "Could not set lock" in str(exc) or "lock on file" in str(exc):
                    try:
                        self._conn = _duckdb_mod.connect(db_path, read_only=True, config={"threads": "1"})
                    except Exception:
                        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
                        self._use_duckdb = False
                        self.active_backend = "sqlite"
                else:
                    raise
        else:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    @property
    def _conn(self) -> Any:
        """Live connection handle.

        Raises after `close()` rather than returning None, so use-after-close
        surfaces as an explicit error instead of an `AttributeError` deep inside
        a query method.
        """
        conn = getattr(self, "_DuckDBCPGStore__conn", None)
        if conn is None:
            raise RuntimeError(
                "DuckDBCPGStore is closed; open a new store or keep a reference "
                "and call close() when finished"
            )
        return conn

    @_conn.setter
    def _conn(self, value: Any) -> None:
        self.__conn = value

    def close(self) -> None:
        """Close the underlying DuckDB or SQLite handle.

        Safe to call more than once. Callers that open a store per invocation
        should use `with DuckDBCPGStore(...) as store:` so the handle is
        released on every path, including exceptions.
        """
        # `getattr` rather than attribute access: `__del__` also runs when
        # `__init__` raised before the handle was assigned.
        conn = getattr(self, "_DuckDBCPGStore__conn", None)
        if conn is None:
            return
        self.__conn = None
        try:
            conn.close()
        except Exception:
            pass

    def __enter__(self) -> DuckDBCPGStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS source_snapshots (
                commit_sha TEXT NOT NULL,
                file_path TEXT NOT NULL,
                source_text TEXT NOT NULL,
                file_sha256 TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (commit_sha, file_path)
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS source_snapshot_manifests (
                commit_sha TEXT PRIMARY KEY,
                manifest_digest TEXT NOT NULL,
                file_count INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_fingerprints (
                qualified_name TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL
            )
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
                ussa_payload BLOB NOT NULL,
                verification_fingerprint TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # Existing local stores need additive, non-destructive migrations.
        for table, column, declaration in (
            ("source_snapshots", "file_sha256", "TEXT NOT NULL DEFAULT ''"),
            ("function_nodes", "verification_fingerprint", "TEXT NOT NULL DEFAULT ''"),
        ):
            cur.execute(f"PRAGMA table_info('{table}')")
            columns = {str(row[1]) for row in cur.fetchall()}
            if column not in columns:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS commit_node_map (
                commit_sha TEXT NOT NULL,
                node_uid TEXT NOT NULL,
                PRIMARY KEY (commit_sha, node_uid)
            )
            """
        )
        # Legacy cpg_blocks/cpg_instructions tables, if present, are not written by
        # current versions. Canonical block/instruction data lives in ussa_payload.
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

    def _resolve_snapshot_commit(self, commit_sha: str) -> str:
        """Resolve symbolic revisions to immutable commits; never persist HEAD as identity."""
        if not commit_sha:
            raise ValueError("A source snapshot requires an immutable Git commit, not an empty label")
        if commit_sha == "working-tree" and not self.allow_unverified_snapshots:
            raise ValueError("A source snapshot requires an immutable Git commit, not a working-tree label")
        if self.repo_path is None:
            if commit_sha in ("HEAD", "head") and not self.allow_unverified_snapshots:
                raise ValueError("HEAD snapshot requires DuckDBCPGStore(repo_path=...) to resolve an immutable commit")
            return commit_sha
        target = "HEAD" if commit_sha.lower() == "head" else commit_sha
        if target.startswith("-") or any(ch.isspace() for ch in target):
            raise ValueError("Malformed source snapshot commit reference")
        proc = subprocess.run(
            ["git", "rev-parse", "--verify", f"{target}^{{commit}}"],
            cwd=str(self.repo_path), capture_output=True, text=True, check=False,
        )
        resolved = proc.stdout.strip().lower()
        if proc.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40,64}", resolved):
            raise ValueError(f"Could not resolve {commit_sha!r} to an immutable Git commit")
        return resolved

    def _validate_snapshot_matches_git(self, commit_sha: str, sources: dict[str, str]) -> None:
        """Reject content labeled as a commit snapshot unless it matches that Git tree."""
        if self.repo_path is None:
            if not self.allow_unverified_snapshots:
                raise LineageIntegrityError(
                    f"Commit-bound source snapshot for {commit_sha!r} requires a valid Git repository "
                    "(or explicit allow_unverified_snapshots=True for test environments)"
                )
            return
        # Only source files are stored by this API; compare the complete set of
        # source-like files in the tree, plus exact bytes for each file.
        source_suffixes = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".c", ".h", ".cc", ".cpp", ".hpp", ".go", ".rs", ".java", ".kt", ".swift", ".rb", ".php", ".sh", ".yaml", ".yml", ".toml", ".json"}
        proc = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "-z", commit_sha],
            cwd=str(self.repo_path), capture_output=True, check=False,
        )
        if proc.returncode != 0:
            raise LineageIntegrityError(f"Could not enumerate tree for commit {commit_sha}")
        tracked_all = {
            item.decode("utf-8", errors="strict")
            for item in proc.stdout.split(b"\0") if item
        }
        supplied = {str(path).replace("\\", "/") for path in sources}
        # The ingest API may snapshot Python-only repositories or a mixed-language
        # source set. Require completeness for every suffix represented in the
        # supplied manifest, without demanding README/build artifacts from callers
        # that intentionally snapshot only source code.
        supplied_suffixes = {Path(path).suffix.lower() for path in supplied}
        tracked = {
            path for path in tracked_all
            if Path(path).suffix.lower() in supplied_suffixes and Path(path).suffix.lower() in source_suffixes
        }
        extra = sorted(supplied - tracked)[:3]
        if extra:
            raise LineageIntegrityError(
                f"Snapshot contains paths absent from the Git source tree at {commit_sha}: {extra}"
            )
        # A snapshot may intentionally be a subset of source paths. Every stored
        # entry is still verified against the immutable tree; omitted paths cannot
        # ground a later deletion and therefore remain fail-closed as missing data.
        for rel_path, text in sources.items():
            # `git show <commit>:<path>` reads a path from the immutable tree,
            # not from the current worktree.
            show = subprocess.run(
                ["git", "show", f"{commit_sha}:{rel_path.replace(chr(92), '/') }"],
                cwd=str(self.repo_path), capture_output=True, check=False,
            )
            if show.returncode != 0 or show.stdout != text.encode("utf-8"):
                raise LineageIntegrityError(f"Source content for {rel_path!r} does not match commit {commit_sha}")

    @staticmethod
    def _snapshot_manifest(sources: dict[str, str], commit_sha: str) -> tuple[dict[str, str], str]:
        hashes = {
            str(path): content_digest_hex(text, domain="verifyci.v2.source_snapshot.file")
            for path, text in sorted(sources.items())
        }
        # The manifest commits to both the immutable revision identity and the
        # canonical path->content-hash map. Re-keying rows to another commit will
        # therefore fail validation even if their individual file digests survive.
        payload = {"commit_sha": commit_sha.lower(), "files": hashes}
        digest = content_digest_hex(
            canonical_jcs_bytes(payload), domain="verifyci.v2.source_snapshot.manifest.v2"
        )
        return hashes, digest

    def record_source_snapshot(self, commit_sha: str, sources: dict[str, str]) -> int:
        """Stores exact source text plus per-file digests and a commit-bound manifest of the stored file set."""
        resolved_sha = self._resolve_snapshot_commit(commit_sha)
        clean_sources = {str(path).replace("\\", "/"): str(text) for path, text in sources.items()}
        self._validate_snapshot_matches_git(resolved_sha, clean_sources)
        hashes, manifest_digest = self._snapshot_manifest(clean_sources, resolved_sha)
        cur = self._conn.cursor()
        try:
            cur.execute("DELETE FROM source_snapshots WHERE commit_sha = ?", (resolved_sha,))
            if clean_sources:
                cur.executemany(
                    "INSERT INTO source_snapshots (commit_sha, file_path, source_text, file_sha256) VALUES (?, ?, ?, ?)",
                    [(resolved_sha, path, text, hashes[path]) for path, text in sorted(clean_sources.items())],
                )
            cur.execute(
                "INSERT OR REPLACE INTO source_snapshot_manifests (commit_sha, manifest_digest, file_count) VALUES (?, ?, ?)",
                (resolved_sha, manifest_digest, len(clean_sources)),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return len(clean_sources)

    def load_source_snapshot(self, commit_sha: str) -> dict[str, str]:
        """Loads a snapshot only after verifying file digests, commit-bound manifest, and immutable Git contents when available."""
        resolved_sha = self._resolve_snapshot_commit(commit_sha)
        cur = self._conn.cursor()
        cur.execute(
            "SELECT file_path, source_text, file_sha256 FROM source_snapshots WHERE commit_sha = ? ORDER BY file_path",
            (resolved_sha,),
        )
        rows = cur.fetchall()
        if not rows and resolved_sha != commit_sha:
            cur.execute(
                "SELECT file_path, source_text, file_sha256 FROM source_snapshots WHERE commit_sha = ? ORDER BY file_path",
                (commit_sha,),
            )
            fallback_rows = cur.fetchall()
            if fallback_rows:
                rows = fallback_rows
                resolved_sha = commit_sha
        cur.execute(
            "SELECT manifest_digest, file_count FROM source_snapshot_manifests WHERE commit_sha = ?",
            (resolved_sha,),
        )
        manifest_row = cur.fetchone()
        if manifest_row is None:
            if rows:
                raise LineageIntegrityError(f"Source snapshot {resolved_sha!r} has no manifest")
            return {}
        sources: dict[str, str] = {}
        expected_hashes: dict[str, str] = {}
        for path, text, file_hash in rows:
            path, text, file_hash = str(path), str(text), str(file_hash)
            actual = content_digest_hex(text, domain="verifyci.v2.source_snapshot.file")
            if not file_hash or actual != file_hash:
                raise LineageIntegrityError(f"Source snapshot file digest mismatch for {resolved_sha}:{path}")
            sources[path] = text
            expected_hashes[path] = actual
        _verified_hashes, actual_manifest = self._snapshot_manifest(sources, resolved_sha)
        if len(rows) != int(manifest_row[1]):
            raise LineageIntegrityError(f"Source snapshot manifest file-count mismatch for {resolved_sha}")
        if actual_manifest != str(manifest_row[0]):
            # Upgrade legacy v1 manifests only after rechecking every stored file
            # against the immutable Git object database. Without Git-backed source
            # proof, an unbound legacy manifest is not promoted to commit evidence.
            legacy_manifest = content_digest_hex(
                canonical_jcs_bytes(expected_hashes), domain="verifyci.v2.source_snapshot.manifest"
            )
            if str(manifest_row[0]) != legacy_manifest or self.repo_path is None:
                raise LineageIntegrityError(f"Source snapshot manifest mismatch for {resolved_sha}")
            self._validate_snapshot_matches_git(resolved_sha, sources)
            cur.execute(
                "UPDATE source_snapshot_manifests SET manifest_digest = ? WHERE commit_sha = ?",
                (actual_manifest, resolved_sha),
            )
            self._conn.commit()
        # Re-check immutable Git contents on every load, not only at write time.
        # This blocks relabeling a DB row to a different commit even if an editor
        # also rewrites its file and manifest digests.
        self._validate_snapshot_matches_git(resolved_sha, sources)
        return sources

    def record_verification_fingerprints(self, fingerprints: dict[str, str], *, replace_all: bool = False) -> None:
        """Persist fingerprints; full replacement removes stale deleted-function keys."""
        cur = self._conn.cursor()
        try:
            if replace_all:
                cur.execute("DELETE FROM verification_fingerprints")
                cur.execute("UPDATE function_nodes SET verification_fingerprint = ''")
            if fingerprints:
                cur.executemany(
                    "INSERT OR REPLACE INTO verification_fingerprints (qualified_name, fingerprint) VALUES (?, ?)",
                    [(name, fp) for name, fp in sorted(fingerprints.items())],
                )
                cur.executemany(
                    "UPDATE function_nodes SET verification_fingerprint = ? WHERE qualified_name = ?",
                    [(fp, name) for name, fp in sorted(fingerprints.items())],
                )
            self._conn.commit()
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass
            raise

    def load_verification_fingerprints(self) -> dict[str, str]:
        cur = self._conn.cursor()
        cur.execute("SELECT qualified_name, fingerprint FROM verification_fingerprints")
        return {str(name): str(fp) for name, fp in cur.fetchall()}

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
                call_uid = content_digest_hex(
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
