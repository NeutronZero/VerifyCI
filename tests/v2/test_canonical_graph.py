"""Unit coverage for the CAP-006 canonical graph digest and lineage locks.

Mutation testing (CAP-013) only proves a guarantee is enforced by a suite that
exercises it. These tests exist so the temporal-replay integrity checks are
covered directly, not only through the benchmark oracle.
"""
from __future__ import annotations

import pytest

from verifyci_v2.store.canonical_graph import (
    LineageIntegrityError,
    canonical_graph_digest,
    clean_snapshot_digest,
    extract_file_semantics,
    replay_digest,
    resolve_snapshot_files,
    snapshot_semantics,
    validate_history,
)

_SRC = "def handler(x):\n    return inner(x)\n"


def test_extraction_records_module_function_and_call_edge() -> None:
    entities, edges = extract_file_semantics("src/a.py", _SRC)

    assert "module:src/a.py" in entities
    func_id = "func:src/a.py:handler"
    assert func_id in entities
    assert entities[func_id].entity_type == "FUNCTION"
    assert entities[func_id].args == ("x",)

    defines = [e for e in edges if e.edge_type == "DEFINES" and e.dst_id == func_id]
    assert defines and defines[0].src_id == "module:src/a.py"

    calls = [e for e in edges if e.edge_type == "CALLS"]
    assert calls and calls[0].callee_name == "inner"


def test_nested_function_is_a_method_with_qualified_name() -> None:
    src = "class C:\n    def m(self, a):\n        return a\n"
    entities, _ = extract_file_semantics("src/c.py", src)

    method_id = "func:src/c.py:C.m"
    assert method_id in entities
    assert entities[method_id].entity_type == "METHOD"
    assert entities[method_id].name == "C.m"


def test_unparseable_source_degrades_to_module_only() -> None:
    entities, edges = extract_file_semantics("src/bad.py", "def (:\n")
    assert list(entities) == ["module:src/bad.py"]
    assert edges == []


def test_digest_is_stable_and_order_independent() -> None:
    files_a = {"src/a.py": _SRC, "src/b.py": "def b():\n    return 1\n"}
    forward = clean_snapshot_digest(files_a)
    reverse = clean_snapshot_digest(dict(reversed(list(files_a.items()))))
    assert forward == reverse, "file iteration order must not change the digest"

    entities, edges = snapshot_semantics(files_a)
    assert canonical_graph_digest(entities, edges) == forward
    # Reordering edges must not change the digest either.
    assert canonical_graph_digest(entities, list(reversed(edges))) == forward


def test_digest_changes_when_content_changes() -> None:
    before = clean_snapshot_digest({"src/a.py": "def a():\n    return 1\n"})
    after = clean_snapshot_digest({"src/a.py": "def a():\n    return 2\n"})
    assert before != after


def test_replay_matches_clean_snapshot_for_equivalent_history() -> None:
    commits = [
        {"commit_id": "c1", "parent_id": None, "files": {"src/a.py": "def a():\n    return 1\n"}},
        {"commit_id": "c2", "parent_id": "c1", "files": {"src/a.py": "def a():\n    return 2\n"}},
    ]
    replayed = replay_digest(commits, "c2")
    clean = clean_snapshot_digest(resolve_snapshot_files(commits, "c2"))
    assert replayed == clean


def test_replay_replaces_snapshot_so_rename_drops_the_old_path() -> None:
    commits = [
        {"commit_id": "c1", "parent_id": None, "files": {"src/old.py": "def f():\n    return 1\n"}},
        {"commit_id": "c2", "parent_id": "c1", "files": {"src/new.py": "def f():\n    return 1\n"}},
    ]
    files = resolve_snapshot_files(commits, "c2")
    assert set(files) == {"src/new.py"}, "a rename must not retain the old path"
    assert "module:src/old.py" not in snapshot_semantics(files)[0]


def test_unknown_parent_fails_closed() -> None:
    commits = [{"commit_id": "c1", "parent_id": "ghost", "files": {}}]
    with pytest.raises(LineageIntegrityError):
        validate_history(commits)


def test_self_cycle_fails_closed() -> None:
    commits = [{"commit_id": "c1", "parent_id": "c1", "files": {}}]
    with pytest.raises(LineageIntegrityError):
        validate_history(commits)


def test_two_commit_cycle_fails_closed() -> None:
    commits = [
        {"commit_id": "c1", "parent_id": "c2", "files": {}},
        {"commit_id": "c2", "parent_id": "c1", "files": {}},
    ]
    with pytest.raises(LineageIntegrityError):
        validate_history(commits)


def test_corrupted_anchor_fails_closed() -> None:
    commits = [
        {"commit_id": "c1", "parent_id": None, "files": {"src/a.py": "x=1\n"}},
        {
            "commit_id": "c2",
            "parent_id": "c1",
            "corrupted_anchor": True,
            "files": {"src/a.py": "x=2\n"},
        },
    ]
    with pytest.raises(LineageIntegrityError):
        replay_digest(commits, "c2")


def test_fabricated_revert_target_fails_closed() -> None:
    commits = [
        {"commit_id": "c1", "parent_id": None, "files": {"src/a.py": "x=1\n"}},
        {
            "commit_id": "c2",
            "parent_id": "c1",
            "fabricated_revert_of": "ghost_revision",
            "files": {"src/a.py": "x=2\n"},
        },
    ]
    with pytest.raises(LineageIntegrityError):
        replay_digest(commits, "c2")


def test_tampered_content_hash_fails_closed() -> None:
    commits = [
        {
            "commit_id": "c1",
            "parent_id": None,
            "files": {"src/a.py": "x=1\n"},
            "tampered_source_hash": "deadbeef" * 8,
        }
    ]
    with pytest.raises(LineageIntegrityError):
        replay_digest(commits, "c1")


def test_unresolved_merge_conflict_fails_closed() -> None:
    commits = [
        {"commit_id": "p1", "parent_id": None, "files": {"src/x.py": "x=1\n"}},
        {"commit_id": "p2", "parent_id": None, "files": {"src/x.py": "x=2\n"}},
        {
            "commit_id": "m",
            "parent_id": None,
            "parent_ids": ["p1", "p2"],
            "unresolved_conflict": True,
            "files": {"src/x.py": "<<<<<<< HEAD\n"},
        },
    ]
    with pytest.raises(LineageIntegrityError):
        replay_digest(commits, "m")


def test_missing_target_commit_fails_closed() -> None:
    commits = [{"commit_id": "c1", "parent_id": None, "files": {}}]
    with pytest.raises(LineageIntegrityError):
        replay_digest(commits, "c_never_existed")


def test_duplicate_commit_id_fails_closed() -> None:
    commits = [
        {"commit_id": "c1", "parent_id": None, "files": {}},
        {"commit_id": "c1", "parent_id": None, "files": {}},
    ]
    with pytest.raises(LineageIntegrityError):
        validate_history(commits)