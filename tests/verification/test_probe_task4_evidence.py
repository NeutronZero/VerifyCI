from types import SimpleNamespace
from verifyci.contracts.evidence import EvidencePack
from verifyci.contracts.evidence import SourceChunk
from verifyci.verification.evidence_verifier import verify_evidence_coverage
def _ent(path, h):
    return SimpleNamespace(file_path=path, source_hash=h)
def _pack(ents, chunks):
    return EvidencePack(query="", entities=ents, relationships=[], source_chunks=chunks, provenance=[], scores={}, retrieval_methods=[], retrieval_timestamp=0.0, graph_revision="")
def test_entities_only_does_not_cover():
    pack = _pack([_ent("a.py", "aaa")], [])
    assert verify_evidence_coverage(pack) is False
def test_mismatched_hash_does_not_cover():
    pack = _pack([_ent("a.py", "aaa")], [SourceChunk(chunk_id="c1", file_path="a.py", line_start=1, line_end=1, content="x", source_hash="bbb")])
    assert verify_evidence_coverage(pack) is False
def test_matching_hash_covers():
    pack = _pack([_ent("a.py", "aaa")], [SourceChunk(chunk_id="c1", file_path="a.py", line_start=1, line_end=1, content="x", source_hash="aaa")])
    assert verify_evidence_coverage(pack) is True
