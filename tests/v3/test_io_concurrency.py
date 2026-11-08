"""Concurrency and Git-plumbing resilience coverage for the Phase 1/2 I/O work.

The performance work made two claims that only hold under parallel execution:
parsing state is per-thread, and Git blob reads are one-shot process calls that
cannot interleave.  Both were untested.  These tests exercise them directly
rather than asserting the absence of a symbol.
"""

from __future__ import annotations

import concurrent.futures
import subprocess
from pathlib import Path

import pytest

from verifyci.scm.git import GitError, GitRepo
from verifyci.scope.entities import analyze_source, analyze_typescript

_PY_SOURCE = (
    "class A:\n"
    "    def f(self, x):\n"
    "        return g(x)\n"
    "\n"
    "def g(x):\n"
    "    return x + 1\n"
)
_TS_SOURCE = "export function f(x: number): number {\n  return g(x);\n}\n"
_LARGE_PY_SOURCE = "\n\n".join(
    f"def fn_{i}(a, b=1, *args, **kw):\n"
    f"    x = a + b\n"
    f"    if x > {i}:\n"
    f"        return [x for _ in range(3)]\n"
    f"    return x\n"
    f"\n"
    f"class C{i}:\n"
    f"    def m(self, v):\n"
    f"        return v\n"
    for i in range(200)
)
_THREADS = 8
_ROUNDS = 64


def _python_snapshot(source: str = _PY_SOURCE) -> tuple[bool, tuple[tuple[str, int, int, str], ...], tuple[tuple[str, int], ...]]:
    facts = analyze_source("mod.py", source)
    return (
        facts.supported,
        tuple((e.qname, e.start_line, e.end_line, e.body_digest) for e in facts.entities),
        tuple((c.callee, c.line) for c in facts.calls),
    )


def _typescript_snapshot() -> tuple[bool, tuple[tuple[str, int, int], ...]]:
    facts = analyze_typescript("mod.ts", _TS_SOURCE)
    return facts.supported, tuple((e.qname, e.start_line, e.end_line) for e in facts.entities)


@pytest.mark.invariant
def test_python_parsing_is_thread_deterministic():
    """Each parse owns its parser, so parallel analysis must agree exactly."""
    expected = _python_snapshot()
    assert expected[0] is True
    assert expected[1], "fixture produced no entities"
    with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as pool:
        results = list(pool.map(lambda _: _python_snapshot(), range(_ROUNDS)))
    mismatches = [r for r in results if r != expected]
    assert not mismatches, f"{len(mismatches)} of {len(results)} parallel parses diverged"


@pytest.mark.invariant
def test_large_module_spans_survive_parallelism():
    """Spans stay in range and identical for a module of a few hundred entities.

    Small fixtures pass even with a broken tree-sitter build; the failures this
    guards against (out-of-range span points, interpreter segfaults) only appear
    on inputs of this size.
    """
    line_count = _LARGE_PY_SOURCE.count("\n") + 1
    expected = _python_snapshot(_LARGE_PY_SOURCE)
    assert expected[0] is True
    assert len(expected[1]) == 600, f"expected 600 entities, got {len(expected[1])}"
    for qname, start_line, end_line, _digest in expected[1]:
        assert 1 <= start_line <= end_line <= line_count, f"{qname} span {start_line}-{end_line} outside 1-{line_count}"
    with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as pool:
        results = list(pool.map(lambda _: _python_snapshot(_LARGE_PY_SOURCE), range(_THREADS * 2)))
    mismatches = [r for r in results if r != expected]
    assert not mismatches, f"{len(mismatches)} of {len(results)} large parallel parses diverged"


@pytest.mark.invariant
def test_typescript_parsing_is_thread_deterministic():
    expected = _typescript_snapshot()
    assert expected[0] is True, "tree-sitter TypeScript grammar unavailable; cannot assert concurrency"
    assert expected[1], "fixture produced no entities"
    with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as pool:
        results = list(pool.map(lambda _: _typescript_snapshot(), range(_ROUNDS)))
    mismatches = [r for r in results if r != expected]
    assert not mismatches, f"{len(mismatches)} of {len(results)} parallel parses diverged"


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


def _repo_with_blobs(tmp_path: Path, count: int = 8) -> tuple[Path, dict[str, bytes]]:
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
def test_parallel_blob_reads_do_not_interleave(tmp_path: Path):
    """One GitRepo, many threads: every read must return exactly its own blob.

    A shared request/response pipe would cross these answers; one-shot drained
    processes cannot.
    """
    root, blobs = _repo_with_blobs(tmp_path)
    expected = dict(blobs)
    order = sorted(expected)

    repo = GitRepo(root)
    try:
        single = {oid: repo.read_blobs([oid])[oid] for oid in order}
        assert single == expected

        def read(oid: str) -> tuple[str, bytes | None]:
            return oid, repo.read_blobs([oid]).get(oid)

        jobs = [order[i % len(order)] for i in range(_ROUNDS)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as pool:
            results = list(pool.map(read, jobs))
    finally:
        repo.close()

    for oid, data in results:
        assert data == expected[oid], f"blob {oid} read back the wrong bytes under concurrency"


@pytest.mark.invariant
def test_batched_blob_read_returns_each_requested_object(tmp_path: Path):
    """A single batched call must map every object id to its own content."""
    root, blobs = _repo_with_blobs(tmp_path)
    repo = GitRepo(root)
    try:
        order = sorted(blobs)
        got = repo.read_blobs(order)
    finally:
        repo.close()
    assert got == {oid: blobs[oid] for oid in order}


@pytest.mark.invariant
def test_missing_blob_fails_closed(tmp_path: Path):
    root, _ = _repo_with_blobs(tmp_path, count=1)
    repo = GitRepo(root)
    try:
        with pytest.raises(GitError) as excinfo:
            repo.read_blob("0" * 40)
    finally:
        repo.close()
    assert excinfo.value.code == "missing_git_object"


@pytest.mark.invariant
def test_unsafe_blob_id_rejected_before_git_runs(tmp_path: Path):
    root, _ = _repo_with_blobs(tmp_path, count=1)
    repo = GitRepo(root)
    try:
        for bad in ("-p", "abc\nHEAD", "abc\r"):
            with pytest.raises(GitError) as excinfo:
                repo.read_blob(bad)
            assert excinfo.value.code == "missing_git_object"
    finally:
        repo.close()


@pytest.mark.invariant
def test_blob_read_timeout_is_bounded_and_recovers(tmp_path: Path, monkeypatch):
    """A hung cat-file must surface as a GitError and leave the adapter usable."""
    from verifyci.scm import git as git_module

    root, blobs = _repo_with_blobs(tmp_path, count=1)
    oid = next(iter(blobs))
    repo = GitRepo(root)
    try:
        monkeypatch.setattr(git_module, "_BATCH_TIMEOUT_SECONDS", 1e-7)
        with pytest.raises(GitError) as excinfo:
            repo.read_blobs([oid])
        assert excinfo.value.code == "internal_fault"
        assert "timed out" in excinfo.value.detail

        # No orphaned child left behind: the adapter still reads correctly.
        monkeypatch.setattr(git_module, "_BATCH_TIMEOUT_SECONDS", 120)
        assert repo.read_blobs([oid])[oid] == blobs[oid]
    finally:
        repo.close()


@pytest.mark.invariant
def test_close_is_idempotent(tmp_path: Path):
    """close() is a documented no-op now that no long-lived child process exists."""
    root, blobs = _repo_with_blobs(tmp_path, count=1)
    oid = next(iter(blobs))
    repo = GitRepo(root)
    assert repo.read_blobs([oid])[oid] == blobs[oid]
    repo.close()
    repo.close()
    assert repo.read_blobs([oid])[oid] == blobs[oid]
