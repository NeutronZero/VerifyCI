"""Rerank-flag passthrough: one flag, every path, same default.

If a refactor renames the flag in one place and not another, the default
path must stay fused-only everywhere. The `methods` list in the result is
the observable pin.
"""
from src.interface.commands.query import run_query
from src.storage.graph_store import GraphStore


def _empty_db(tmp_path):
    db = str(tmp_path / "q.db")
    GraphStore(db).close()
    return db


def test_default_path_is_fused_only(tmp_path):
    result = run_query("anything", db_path=_empty_db(tmp_path), k=5)
    assert not any(m.startswith("rerank") for m in result["methods"])
    assert "rrf" in result["methods"]


def test_rerank_flag_reaches_pipeline(tmp_path):
    result = run_query("anything", db_path=_empty_db(tmp_path), k=5, rerank=True)
    assert any(m.startswith("rerank") for m in result["methods"])
