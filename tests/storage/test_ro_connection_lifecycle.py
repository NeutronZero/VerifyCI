"""CAP-008: Read-Only Connection Lifecycle & Cache Hardening Tests.

Validates the architectural safety guarantees of GraphStore(read_only=True):
1. Connection lifecycle: Normal public close() immediately releases the SQLite handle,
   allowing immediate database file and temporary directory deletion on Windows.
   Explicit force=True also cleanly releases. Direct conn.close() cleans up cache.
2. Cache invalidation & path reuse: Creating DB A at path X, caching, destroying DB A,
   creating DB B at path X, and opening a reader observes DB B, not stale DB A.
3. Bounded cache: Exercising many distinct DB paths within one process enforces
   the LRU eviction ceiling (MAX_RO_CACHE_ENTRIES) without leaking file handles.
"""
from __future__ import annotations

import os
from pathlib import Path
import time


from verifyci.contracts.revision import Revision
from verifyci.storage.graph_store import GraphStore, MAX_RO_CACHE_ENTRIES, _PROCESS_RO_CACHE


def _create_sample_db(db_path: str, rev_id: str = "rev_1") -> None:
    """Helper to initialize a valid VerifyCI WAL database with a revision."""
    store = GraphStore(db_path)
    rev = Revision(
        revision_id=rev_id,
        repository_id="repo_test",
        commit_id="c_test",
        parent_revision_id=None,
        source_hash="h_test",
        timestamp=time.time(),
        ingestion_config_hash="cfg_test",
    )
    store.insert_revision(rev)
    store.close()


def test_ro_connection_lifecycle_normal_close_allows_deletion(tmp_path: Path):
    """Test 1A: Public store.close() releases file handles so files/dirs can be deleted immediately on Windows."""
    GraphStore.clear_ro_cache()
    db_file = tmp_path / "lifecycle.db"
    _create_sample_db(str(db_file), "rev_initial")

    store = GraphStore(str(db_file), read_only=True)
    norm_key = os.path.abspath(str(db_file))
    assert norm_key in _PROCESS_RO_CACHE
    assert store.latest_revision_id("repo_test") == "rev_initial"

    # Normal public close
    store.close()
    assert norm_key not in _PROCESS_RO_CACHE

    # Must be immediately deletable on Windows NTFS without PermissionError
    os.remove(str(db_file))
    assert not db_file.exists()


def test_ro_connection_lifecycle_force_close_and_direct_conn_close(tmp_path: Path):
    """Test 1B: store.close(force=True) and direct conn.close() cleanly release handles."""
    GraphStore.clear_ro_cache()
    db_file = tmp_path / "lifecycle_force.db"
    _create_sample_db(str(db_file), "rev_force")

    # 1. Test close(force=True)
    store1 = GraphStore(str(db_file), read_only=True)
    norm_key = os.path.abspath(str(db_file))
    assert norm_key in _PROCESS_RO_CACHE
    store1.close(force=True)
    assert norm_key not in _PROCESS_RO_CACHE

    # 2. Test direct conn.close()
    store2 = GraphStore(str(db_file), read_only=True)
    assert norm_key in _PROCESS_RO_CACHE
    store2.conn.close()
    assert norm_key not in _PROCESS_RO_CACHE

    # Verify handle is fully released
    os.remove(str(db_file))
    assert not db_file.exists()


def test_ro_cache_invalidation_and_path_reuse(tmp_path: Path):
    """Test 2: Creating DB A at path X, caching, destroying DB A, creating DB B at path X,

    and opening a reader proves it sees DB B, not a stale connection to DB A.
    """
    GraphStore.clear_ro_cache()
    db_file = tmp_path / "reuse_target.db"
    db_path_str = str(db_file)

    # Step 1: Create DB A at path X with rev_A
    _create_sample_db(db_path_str, "rev_alpha")
    store_a = GraphStore(db_path_str, read_only=True)
    assert store_a.latest_revision_id("repo_test") == "rev_alpha"
    store_a.close()

    # Step 2: Destroy DB A
    os.remove(db_path_str)
    # Remove sidecars if present
    for sidecar in [f"{db_path_str}-wal", f"{db_path_str}-shm"]:
        if os.path.exists(sidecar):
            os.remove(sidecar)
    time.sleep(0.02)

    # Step 3: Create DB B at the exact same path X with rev_B
    _create_sample_db(db_path_str, "rev_beta")

    # Step 4: Open reader at path X and prove it sees rev_beta
    store_b = GraphStore(db_path_str, read_only=True)
    observed = store_b.latest_revision_id("repo_test")
    assert observed == "rev_beta", f"Stale cache hit! Expected rev_beta, got {observed}"
    store_b.close()


def test_ro_cache_stale_signature_invalidation_on_disk_replacement(tmp_path: Path):
    """Test 2B: Even if DB file is replaced/rebuilt without closing an existing store instance,

    the file signature (mtime/size) check evicts stale connection and reconnects.
    """
    GraphStore.clear_ro_cache()
    db_file = tmp_path / "sig_invalidation.db"
    db_path_str = str(db_file)

    _create_sample_db(db_path_str, "rev_1")
    store1 = GraphStore(db_path_str, read_only=True)
    assert store1.latest_revision_id("repo_test") == "rev_1"

    # Sleep slightly to guarantee mtime_ns change, then overwrite file
    time.sleep(0.05)
    _create_sample_db(db_path_str, "rev_overwritten")

    # Second store instance at same path must detect file signature change
    store2 = GraphStore(db_path_str, read_only=True)
    assert store2.latest_revision_id("repo_test") == "rev_overwritten"
    store1.close()
    store2.close()


def test_ro_bounded_cache_lru_eviction(tmp_path: Path):
    """Test 3: Exercising many distinct DB paths within one process enforces MAX_RO_CACHE_ENTRIES

    ceiling via LRU eviction without leaking file descriptors.
    """
    GraphStore.clear_ro_cache()
    total_dbs = MAX_RO_CACHE_ENTRIES * 3  # e.g. 48 distinct databases
    db_paths: list[str] = []

    for i in range(total_dbs):
        p = str(tmp_path / f"bounded_{i}.db")
        _create_sample_db(p, f"rev_{i}")
        db_paths.append(p)

    # Open readers across all distinct DBs without calling close()
    stores: list[GraphStore] = []
    for p in db_paths:
        s = GraphStore(p, read_only=True)
        stores.append(s)

    # Verify cache never exceeds the bounded ceiling
    assert len(_PROCESS_RO_CACHE) <= MAX_RO_CACHE_ENTRIES
    assert len(_PROCESS_RO_CACHE) == MAX_RO_CACHE_ENTRIES

    # Verify LRU behavior: the most recently accessed DBs are in cache
    recent_keys = [os.path.abspath(p) for p in db_paths[-MAX_RO_CACHE_ENTRIES:]]
    for rk in recent_keys:
        assert rk in _PROCESS_RO_CACHE

    # Clear cache and verify total release
    GraphStore.clear_ro_cache()
    assert len(_PROCESS_RO_CACHE) == 0
