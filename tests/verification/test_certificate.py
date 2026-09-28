from types import SimpleNamespace

from src.verification.semi_formal_reason import SemiFormalReasoner


def _payload(eid, name="func", path="src/app.py"):
    return SimpleNamespace(
        revision_entity_id=eid, logical_entity_id=f"logical:{eid}",
        name=name, file_path=path, line_start=10, line_end=20,
        source_hash="abc123",
    )


DIFF_APP = (
    "diff --git a/src/app.py b/src/app.py\n"
    "--- a/src/app.py\n"
    "+++ b/src/app.py\n"
    "@@ -1 +1 @@\n"
    "-x = 1\n+x = 2\n"
)


class FakeGraph:
    """Graph fake with optional call edges: {src_idx: [dst_idx]}."""

    def __init__(self, payloads, calls=None):
        self._payloads = payloads
        self._calls = calls or {}
        self._rcalls = {}
        for src, dsts in self._calls.items():
            for dst in dsts:
                self._rcalls.setdefault(dst, []).append(src)

    def nodes(self):
        return list(self._payloads)

    def node_indices(self):
        return list(range(len(self._payloads)))

    def predecessors(self, idx):
        return list(self._rcalls.get(idx, []))

    def successors(self, idx):
        return list(self._calls.get(idx, []))


def test_mapped_diff_verifies_with_seed_evidence():
    graph = FakeGraph([_payload("e1"), _payload("e2")])
    cert = SemiFormalReasoner().verify(DIFF_APP, graph)
    assert cert.certificate_verified is True
    assert cert.conclusion.result == "pass"
    assert [p.statement for p in cert.premises] == ["file_changed:src/app.py"]
    assert {t.path[0] for t in cert.execution_traces} == {"e1", "e2"}
    assert len(cert.evidence) == 2
    assert all(e.file_path == "src/app.py" and e.source_hash == "abc123" for e in cert.evidence)
    assert cert.confidence == 1.0


def test_caller_trace_follows_call_edges():
    graph = FakeGraph([_payload("e1", name="callee"), _payload("e2", name="caller")],
                      calls={1: [0]})
    cert = SemiFormalReasoner().verify(DIFF_APP, graph)
    assert cert.certificate_verified is True
    paths = [t.path for t in cert.execution_traces]
    assert ["e2", "e1"] in paths  # caller -> callee edge traced


def test_gibberish_diff_is_inconclusive():
    graph = FakeGraph([_payload("e1")])
    cert = SemiFormalReasoner().verify("def f(): pass  # not a diff", graph)
    assert cert.certificate_verified is False
    assert cert.conclusion.result == "inconclusive"
    assert cert.premises == []
    assert cert.execution_traces == []


def test_unknown_file_diff_is_inconclusive():
    graph = FakeGraph([_payload("e1")])
    diff = DIFF_APP.replace("src/app.py", "src/ghost.py")
    cert = SemiFormalReasoner().verify(diff, graph)
    assert cert.certificate_verified is False
    assert cert.conclusion.result == "inconclusive"
    assert [p.statement for p in cert.premises] == ["file_changed:src/ghost.py"]
    assert cert.evidence == []


def test_opaque_graph_is_inconclusive():
    cert = SemiFormalReasoner().verify(DIFF_APP, object())
    assert cert.certificate_verified is False
    assert cert.conclusion.result == "inconclusive"
    assert cert.execution_traces == []
    assert cert.evidence == []
    assert cert.confidence < 1.0


def test_none_graph_is_inconclusive():
    cert = SemiFormalReasoner().verify(DIFF_APP, None)
    assert cert.certificate_verified is False
    assert cert.conclusion.result == "inconclusive"


def test_empty_diff_never_verifies_even_with_graph():
    graph = FakeGraph([_payload("e1")])
    for diff in ("", "   ", None):
        cert = SemiFormalReasoner().verify(diff, graph)
        assert cert.certificate_verified is False
        assert cert.conclusion.result == "inconclusive"


def test_graph_without_file_evidence_does_not_verify():
    graph = FakeGraph([SimpleNamespace(name="x")])
    cert = SemiFormalReasoner().verify(DIFF_APP, graph)
    assert cert.certificate_verified is False
    assert cert.evidence == []
