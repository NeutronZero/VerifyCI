"""Unit tests for small pure helpers previously covered only indirectly."""
import sys

from src.ingestion.extractor import _source_snippet
from src.ingestion.language import detect_language, is_ingestible
from src.memory.ledger import EventLedger
from src.orchestration.compiler.permissions import check_permission
from src.orchestration.events import emit_event
from src.orchestration.executor import _get
from src.orchestration.scheduler import _levels, _topo_order
from src.tools.file_read import file_read_tool
from src.tools.file_write import file_write_tool
from src.tools.sandbox import run_sandboxed


def test_topo_order_chain():
    nodes = [
        {"step_id": "c", "depends_on": ["b"]},
        {"step_id": "a", "depends_on": []},
        {"step_id": "b", "depends_on": ["a"]},
    ]
    assert [n["step_id"] for n in _topo_order(nodes)] == ["a", "b", "c"]


def test_topo_order_cycle_raises():
    import pytest
    with pytest.raises(ValueError, match="cycle_detected"):
        _topo_order([
            {"step_id": "a", "depends_on": ["b"]},
            {"step_id": "b", "depends_on": ["a"]},
        ])


def test_levels_groups_independent_nodes():
    nodes = [
        {"step_id": "a", "depends_on": []},
        {"step_id": "b", "depends_on": []},
        {"step_id": "c", "depends_on": ["a", "b"]},
    ]
    levels = _levels(nodes)
    assert {n["step_id"] for n in levels[0]} == {"a", "b"}
    assert [n["step_id"] for n in levels[1]] == ["c"]


def test_is_ingestible():
    assert is_ingestible("a.py") is True
    assert is_ingestible("A.CPP") is True
    assert is_ingestible("notes.md") is True
    assert is_ingestible("data.json") is False
    assert is_ingestible("Makefile") is False


def test_run_sandboxed_echo():
    result = run_sandboxed([sys.executable, "-c", "print('hi')"])
    assert result["returncode"] == 0
    assert result["stdout"].strip() == "hi"


def test_get_dict_and_namespace():
    from types import SimpleNamespace
    assert _get({"a": 1}, "a") == 1
    assert _get({"a": 1}, "missing", "dflt") == "dflt"
    assert _get(SimpleNamespace(a=2), "a") == 2
    assert _get(None, "a") is None


def test_emit_event_appends():
    ledger = EventLedger()
    event = emit_event(ledger, "T", {"k": "v"}, {"s": "test"})
    assert event.type == "T"
    assert ledger.get_events() == [event]


def test_file_write_read_round_trip(tmp_path):
    path = str(tmp_path / "sub" / "note.txt")
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    assert file_write_tool(path, "hello")["success"] is True
    result = file_read_tool(path)
    assert result["content"] == "hello"
    assert result["error"] is None


def test_file_read_missing():
    result = file_read_tool("/nonexistent-verifyci-probe/x.txt")
    assert result["content"] is None
    assert result["error"]


def test_source_snippet_out_of_bounds():
    src = b"line1\nline2\n"
    assert _source_snippet(src, 1, 2) == "line1\nline2"
    assert _source_snippet(src, 10, 20) == ""
    assert _source_snippet(src, -5, 1) == "line1"
    assert _source_snippet(src, 2, 1) == ""


def test_detect_language_unknown():
    assert detect_language("x.unknown-ext") == "unknown"


def test_check_permission_deny():
    assert check_permission("rm_rf_everything") is False
