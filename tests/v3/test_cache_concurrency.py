"""Concurrency, bounded caching, and stream robustness tests for VerifyCI."""

from __future__ import annotations

import concurrent.futures
from pathlib import Path
import subprocess
from typing import Any

import pytest

from verifyci.index.cache import CacheStore
from verifyci.index.provider import FactProvider
from verifyci.scm.git import GitError, GitRepo


def _make_components(path: str, blob_hash: str) -> dict[str, Any]:
    return FactProvider.tier1_components(
        toolchain_fingerprint="test-tc",
        blob_hash=blob_hash,
        path=path,
        language_id="python",
        frontend_version="1.0",
        source_roots=(),
    )


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr or result.stdout}")
    return result.stdout.strip()


def _repo_with_blobs(tmp_path: Path, count: int = 20) -> tuple[Path, dict[str, bytes]]:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "VerifyCI Test")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "core.autocrlf", "false")
    payloads: dict[str, bytes] = {}
    for index in range(count):
        rel = f"src/mod_{index}.py"
        body = f"def f_{index}():\n    return {index}\n".encode("utf-8")
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        payloads[rel] = body
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "base")
    commit = _git(root, "rev-parse", "HEAD")
    blob_ids: dict[str, str] = {}
    for line in _git(root, "ls-tree", "-r", commit).splitlines():
        meta, rel = line.split("\t", 1)
        blob_ids[rel] = meta.split(" ")[2]
    return root, {blob_ids[rel]: payloads[rel] for rel in payloads}


@pytest.mark.invariant
def test_fact_provider_stats_concurrency():
    """Concurrent get_or_compute calls without cache must synchronize stats accurately."""
    provider = FactProvider(cache_store=None)
    rounds_per_thread = 200
    threads = 8
    total_calls = rounds_per_thread * threads

    def worker(worker_id: int) -> None:
        for i in range(rounds_per_thread):
            components = _make_components(f"src/file_{worker_id}_{i}.py", f"hash_{worker_id}_{i}")
            provider.get_or_compute("entity_spans", components, lambda idx=i: [{"span": idx}])

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, t) for t in range(threads)]
        concurrent.futures.wait(futures)
        for f in futures:
            f.result()

    stats = provider.cache_stats()
    assert stats["misses"] == total_calls
    assert stats["hits"] == 0
    assert stats["writes"] == 0


@pytest.mark.invariant
def test_fact_provider_concurrent_hits_and_misses(tmp_path: Path):
    """Concurrent calls across threads correctly update hits, misses, and writes without drift."""
    cache_dir = tmp_path / "cache"
    store = CacheStore(cache_dir, mode="local")
    provider = FactProvider(store)

    key_count = 10
    components_list = [
        _make_components(f"src/mod_{k}.py", f"hash_{k:040x}")
        for k in range(key_count)
    ]

    threads = 8
    rounds = 50
    total_calls = threads * rounds

    def worker(worker_id: int) -> None:
        for i in range(rounds):
            comp = components_list[(worker_id + i) % key_count]
            val = provider.get_or_compute("entity_spans", comp, lambda: [{"val": 1}])
            assert val == [{"val": 1}]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, t) for t in range(threads)]
        concurrent.futures.wait(futures)
        for f in futures:
            f.result()

    stats = provider.cache_stats()
    assert stats["hits"] + stats["misses"] == total_calls
    assert stats["misses"] >= key_count
    assert stats["writes"] == stats["misses"]

    # In a subsequent warm-cache pass, every call must be a hit
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, t) for t in range(threads)]
        concurrent.futures.wait(futures)
        for f in futures:
            f.result()

    warm_stats = provider.cache_stats()
    assert warm_stats["misses"] == stats["misses"]
    assert warm_stats["writes"] == stats["writes"]
    assert warm_stats["hits"] == stats["hits"] + total_calls


@pytest.mark.invariant
def test_cache_store_concurrent_put_same_key(tmp_path: Path):
    """Concurrent threads writing to the identical cache key do not collide on temp files."""
    cache_dir = tmp_path / "cache"
    store = CacheStore(cache_dir, mode="local")
    comp = _make_components("src/common.py", "c" * 40)

    threads = 16
    rounds = 20

    def worker(worker_id: int) -> list[bool]:
        results = []
        for i in range(rounds):
            success = store.put("entity_spans", comp, [{"thread": worker_id, "round": i}])
            results.append(success)
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, t) for t in range(threads)]
        concurrent.futures.wait(futures)
        for f in futures:
            assert all(f.result()), "All concurrent put operations must succeed"

    # Confirm cache entry is valid and readable
    val, hit = store.get("entity_spans", comp)
    assert hit is True
    assert isinstance(val, list) and len(val) == 1

    # Confirm no orphaned .tmp files remain in shard directory
    shard = store.entry_key("entity_spans", comp)[:2]
    tmp_files = list((cache_dir / shard).glob("*.tmp"))
    assert not tmp_files, f"Orphaned temporary files found: {tmp_files}"


@pytest.mark.invariant
def test_cache_store_concurrent_ensure_shard(tmp_path: Path):
    """Concurrent shard creation and registration is thread-safe."""
    cache_dir = tmp_path / "cache"
    store = CacheStore(cache_dir, mode="local")

    threads = 12
    rounds = 30

    def worker(worker_id: int) -> None:
        for i in range(rounds):
            comp = _make_components(f"src/{worker_id}_{i}.py", f"{worker_id:020x}{i:020x}")
            assert store.put("entity_spans", comp, {"data": i}) is True

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, t) for t in range(threads)]
        concurrent.futures.wait(futures)
        for f in futures:
            f.result()

    assert len(store._created_shards) > 0
    # Every created shard dir actually exists on disk
    for shard in store._created_shards:
        assert (cache_dir / shard).is_dir()


@pytest.mark.invariant
def test_git_repo_blob_cache_bounded_lru(tmp_path: Path):
    """GitRepo _blob_cache enforces maximum size with LRU eviction."""
    root, blobs = _repo_with_blobs(tmp_path, count=20)
    max_size = 5
    repo = GitRepo(root, max_cache_size=max_size)
    try:
        oid_list = list(blobs.keys())

        # Read first 5 blobs
        for oid in oid_list[:5]:
            repo.read_blob(oid)
        assert len(repo._blob_cache) <= max_size

        # Read next 15 blobs, exceeding capacity
        for oid in oid_list[5:]:
            repo.read_blob(oid)
            assert len(repo._blob_cache) <= max_size

        # Cache size must not exceed ceiling
        assert len(repo._blob_cache) == max_size

        # The most recent blob must be present in the cache
        most_recent = oid_list[-1]
        assert most_recent in repo._blob_cache

        # Access an older blob; it should be evicted and re-read, still within limit
        old_blob = oid_list[0]
        data = repo.read_blob(old_blob)
        assert data == blobs[old_blob]
        assert len(repo._blob_cache) == max_size
        assert old_blob in repo._blob_cache
    finally:
        repo.close()


@pytest.mark.invariant
def test_git_repo_tree_cache_bounded_lru(tmp_path: Path):
    """GitRepo _tree_cache enforces maximum size ceiling."""
    root, _ = _repo_with_blobs(tmp_path, count=1)
    max_size = 3
    repo = GitRepo(root, max_cache_size=max_size)
    try:
        # Create multiple dummy tree entries
        for i in range(10):
            repo._tree_cache[f"rev_{i}"] = {}
            repo._tree_cache.move_to_end(f"rev_{i}")
            while len(repo._tree_cache) > repo._max_cache_size:
                repo._tree_cache.popitem(last=False)
        assert len(repo._tree_cache) == max_size
        assert "rev_9" in repo._tree_cache
        assert "rev_0" not in repo._tree_cache
    finally:
        repo.close()


@pytest.mark.invariant
def test_git_repo_read_blobs_truncated_stdout_raises(tmp_path: Path, monkeypatch):
    """Short stdout reads from cat-file --batch must raise internal_fault rather than breaking prematurely."""
    root, blobs = _repo_with_blobs(tmp_path, count=3)
    repo = GitRepo(root)
    oids = list(blobs.keys())

    # Mock subprocess.run to return prematurely truncated stdout
    real_run = subprocess.run

    def mock_run(command, *args, **kwargs):
        res = real_run(command, *args, **kwargs)
        if "cat-file" in command:
            # Truncate stdout to only the first 10 bytes (cutting off mid-header or before remaining blobs)
            return subprocess.CompletedProcess(
                args=command,
                returncode=0,
                stdout=res.stdout[:10],
                stderr=res.stderr,
            )
        return res

    monkeypatch.setattr(subprocess, "run", mock_run)
    try:
        with pytest.raises(GitError) as excinfo:
            repo.read_blobs(oids)
        assert excinfo.value.code == "internal_fault"
        assert "unexpected EOF" in excinfo.value.detail or "truncated" in excinfo.value.detail
    finally:
        repo.close()
