"""PROBE item 1: _carry_forward must not resurrect removed DEPENDS_ON edges."""
from verifyci.interface.commands.ingest import run_ingest
from verifyci.storage.graph_store import GraphStore


def test_probe_incremental_requirement_removal_drops_stale_edge(tmp_path):
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x = 1\n")
    (repo / "requirements.txt").write_text("requests==2.0\nflask==3.0\n")
    out1 = run_ingest(str(repo))
    (repo / "requirements.txt").write_text("requests==2.0\n")
    out2 = run_ingest(str(repo), incremental=True)
    assert out2["revision_id"] != out1["revision_id"]
    store = GraphStore(out2["db_path"])
    try:
        deps = [e for e in store.get_edges_by_revision(out2["revision_id"])
                if e.type.value == "DEPENDS_ON"]
        pkgs = sorted((e.metadata.get("package") for e in deps), key=lambda p: str(p))
        assert "requests" in pkgs
        assert "flask" not in pkgs, "stale edge resurrected: %s" % (pkgs,)
    finally:
        store.close()
