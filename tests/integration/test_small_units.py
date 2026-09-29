"""Unit tests for small pure helpers previously covered only indirectly."""
from src.ingestion.extractor import _source_snippet
from src.ingestion.language import detect_language, is_ingestible
from src.memory.ledger import EventLedger
from src.orchestration.events import emit_event
from src.orchestration.executor import _get
from src.orchestration.scheduler import _levels, _topo_order


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


def test_source_snippet_out_of_bounds():
    src = b"line1\nline2\n"
    assert _source_snippet(src, 1, 2) == "line1\nline2"
    assert _source_snippet(src, 10, 20) == ""
    assert _source_snippet(src, -5, 1) == "line1"
    assert _source_snippet(src, 2, 1) == ""


def test_detect_language_unknown():
    assert detect_language("x.unknown-ext") == "unknown"


def test_run_stats_empty_db_counts_zero(tmp_path):
    import sqlite3
    from src.interface.commands.stats import run_stats
    db = str(tmp_path / "empty.db")
    sqlite3.connect(db).close()
    stats = run_stats(db)
    assert stats["db_path"] == db
    for table in ("revisions", "entities", "edges", "events", "anchors", "deltas"):
        assert stats[table] == 0


def test_run_vuln_skips_invalid_json_metadata(tmp_path):
    import sqlite3
    from src.interface.commands.vuln import run_vuln
    db = str(tmp_path / "v.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE edges (metadata_json TEXT, type TEXT)")
    conn.execute(
        "INSERT INTO edges VALUES (?, ?)", ("{not json", "DEPENDS_ON"))
    conn.execute(
        "INSERT INTO edges VALUES (?, ?)",
        ('{"package": "pkg-a"}', "DEPENDS_ON"))
    conn.commit()
    conn.close()
    result = run_vuln(db, cache_path=str(tmp_path / "cache.db"))
    assert result["packages_checked"] == 2
    assert result["findings"] == []


def test_run_vuln_reports_unreadable_db(tmp_path):
    # A scan that never ran must not look like a clean scan: wrong path
    # and schema-less DBs surface "error" instead of empty findings.
    from src.interface.commands.vuln import run_vuln
    bad_dir = run_vuln(str(tmp_path / "no-such-dir" / "v.db"),
                       cache_path=str(tmp_path / "cache.db"))
    assert bad_dir["findings"] == []
    assert "error" in bad_dir
    import sqlite3
    empty = str(tmp_path / "empty.db")
    sqlite3.connect(empty).close()
    no_schema = run_vuln(empty, cache_path=str(tmp_path / "cache.db"))
    assert no_schema["findings"] == []
    assert "error" in no_schema
