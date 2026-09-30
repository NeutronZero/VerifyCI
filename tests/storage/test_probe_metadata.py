"""PROBE item 7: MetadataStore.upsert_file commits when it owns the connection."""


def test_probe_upsert_standalone_persists(tmp_path):
    from verifyci.storage.metadata import MetadataStore
    db = str(tmp_path / "m.db")
    m = MetadataStore(db)
    assert m._owns_conn is True
    m.upsert_file("/x/a.py", "h", "python", "r1")
    m.close()
    m2 = MetadataStore(db)
    try:
        row = m2.get_file("/x/a.py")
        assert row is not None and row[1] == "h", row
    finally:
        m2.close()
