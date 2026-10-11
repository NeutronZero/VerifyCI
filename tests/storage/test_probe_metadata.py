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


def test_failed_schema_setup_closes_owned_connection(tmp_path, monkeypatch):
    # Same half-open guarantee as GraphStore/open_for_read: construction
    # failing after connect must close what the caller never receives.
    import sqlite3
    import pytest
    import verifyci.storage.metadata as md
    real_connect = sqlite3.connect
    made = {}

    class FailExecute:
        def __init__(self, real):
            self._real = real
            self.closed = False

        def execute(self, *a, **k):
            raise sqlite3.OperationalError("boom")

        def commit(self):
            pass

        def close(self):
            self.closed = True
            self._real.close()

    def boom_connect(*a, **k):
        fake = FailExecute(real_connect(*a, **k))
        made["conn"] = fake
        return fake

    monkeypatch.setattr(md.sqlite3, "connect", boom_connect)
    with pytest.raises(sqlite3.OperationalError):
        md.MetadataStore(str(tmp_path / "m.db"))
    assert made["conn"].closed
