"""Unit tests for small pure helpers previously covered only indirectly."""
from verifyci.ingestion.extractor import _source_snippet
from verifyci.ingestion.language import detect_language, is_ingestible
from verifyci.memory.ledger import EventLedger
from verifyci.orchestration.events import emit_event
from verifyci.orchestration.executor import _get
from verifyci.orchestration.scheduler import _levels, _topo_order


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
    assert event is not None
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
    from verifyci.interface.commands.stats import run_stats
    db = str(tmp_path / "empty.db")
    sqlite3.connect(db).close()
    stats = run_stats(db)
    assert stats["db_path"] == db
    for table in ("revisions", "entities", "edges", "events", "anchors", "deltas"):
        assert stats[table] == 0
    assert stats["resolution"] == {"resolved": 0, "ambiguous": 0, "missing": 0}


def test_run_stats_reports_resolution_coverage(tmp_path):
    # Resolver coverage is operator-visible: resolved vs ambiguous vs
    # missing, plus stored unresolved edges awaiting a unique target.
    from verifyci.contracts.edge import Edge, EdgeType
    from verifyci.contracts.entity import Entity, EntityType
    from verifyci.interface.commands.stats import run_stats
    from verifyci.storage.graph_store import GraphStore
    from verifyci.storage.revision import create_revision
    db = str(tmp_path / "v.db")
    store = GraphStore(db)
    try:
        revision = create_revision(repository_id="r", files=[("a.py", "h")])
        store.insert_revision(revision)
        rev = revision.revision_id

        def _ent(eid, name, type_=EntityType.FUNCTION):
            return Entity(
                repository_id="r", logical_entity_id="a" * 63 + eid,
                revision_entity_id="b" * 63 + eid, type=type_, name=name,
                file_path="a.py", line_start=1, line_end=2, language="python",
                source_hash="h", revision_id=rev)

        for eid, name in [("1", "user"), ("2", "helper")]:
            store.insert_entity(_ent(eid, name))
        store.insert_edge(Edge(
            id="u1", revision_id=rev, src_entity_id="b" * 63 + "1", dst_entity_id="",
            type=EdgeType.CALLS_UNRESOLVED,
            metadata={"callee": "helper", "caller_scope": ""}))
        store.insert_edge(Edge(
            id="u2", revision_id=rev, src_entity_id="b" * 63 + "1", dst_entity_id="",
            type=EdgeType.CALLS_UNRESOLVED,
            metadata={"callee": "nobody", "caller_scope": ""}))
    finally:
        store.close()
    resolution = run_stats(db)["resolution"]
    assert resolution["resolved"] == 1
    assert resolution["missing"] == 1
    assert resolution["ambiguous"] == 0
    assert resolution["unresolved_edges"] == 2


def test_run_vuln_skips_invalid_json_metadata(tmp_path):
    import sqlite3
    from verifyci.interface.commands.vuln import run_vuln
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
    from verifyci.interface.commands.vuln import run_vuln
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


def test_run_deps_skips_verifyci(tmp_path):
    from verifyci.interface.commands.deps import run_deps
    (tmp_path / 'requirements.txt').write_text('requests==2.0\n')
    vdir = tmp_path / '.verifyci'
    vdir.mkdir()
    (vdir / 'requirements.txt').write_text('requests==2.0\n')
    out = run_deps(str(tmp_path))
    assert any('requirements.txt' in k and '.verifyci' not in k for k in out)
    assert not any('.verifyci' in k for k in out)


def test_run_evaluate_keys():
    from verifyci.interface.commands.evaluate import run_evaluate
    out = run_evaluate()
    for k in ('ledger_chain', 'replay_equivalence', 'event_replay', 'invariant_metrics'):
        assert k in out


def test_run_init_creates_db(tmp_path):
    import os
    from verifyci.interface.commands.init import run_init
    db = run_init(str(tmp_path))
    assert os.path.exists(db)
    assert db.endswith('.verifyci' + '/' + 'verifyci.db') or 'verifyci.db' in db


def test_provenance_and_graph_schema_imports():
    from verifyci.contracts import provenance as prov
    from verifyci.contracts import graph_schema as gs
    assert hasattr(prov, 'validate_provenance_chain')
    assert hasattr(gs, 'GRAPH_TYPES')
    assert hasattr(gs, 'NODE_PROPERTIES')
    # P0 soundness: canonical 7-field provenance records validate;
    # legacy 3-field dicts and raw strings are rejected.
    assert prov.validate_provenance_chain([{
        'entry_id': 'prov_e1', 'entity_id': 'e1', 'file_path': 'a',
        'line_start': 1, 'line_end': 2, 'source_hash': 'h', 'revision_id': 'r',
    }]) is True
    assert prov.validate_provenance_chain([{ 'file_path': 'a', 'source_hash': 'h', 'revision_id': 'r'}]) is False
    assert prov.validate_provenance_chain([{ 'file_path': 'a'}]) is False
