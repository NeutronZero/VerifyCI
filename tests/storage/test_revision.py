from src.storage.revision import canonical_manifest, create_revision


def _files():
    return [("b.py", "h2"), ("a.py", "h1")]


def test_same_state_same_id_despite_time_and_order():
    r1 = create_revision("repo", files=_files())
    r2 = create_revision("repo", files=list(reversed(_files())))
    assert r1.revision_id == r2.revision_id
    assert r1.source_hash == r2.source_hash
    assert len(r1.revision_id) == 64


def test_state_change_new_id():
    r1 = create_revision("repo", files=_files())
    r2 = create_revision("repo", files=[("a.py", "CHANGED"), ("b.py", "h2")])
    assert r1.revision_id != r2.revision_id


def test_commit_bound_to_identity():
    r1 = create_revision("repo", commit_id="abc", files=_files())
    r2 = create_revision("repo", commit_id="def", files=_files())
    assert r1.revision_id != r2.revision_id


def test_empty_manifest_deterministic():
    r1 = create_revision("repo")
    r2 = create_revision("repo")
    assert r1.revision_id == r2.revision_id


def test_manifest_canonical_bytes():
    raw = canonical_manifest("repo", None, None, _files())
    import json
    parsed = json.loads(raw)
    assert [f["path"] for f in parsed["files"]] == ["a.py", "b.py"]
