from types import SimpleNamespace
from verifyci.verification.diffmap import parse_diff_files
from verifyci.verification.diffmap import unattributed_removed_lines
from verifyci.verification.diffmap import find_deletion_hunks
from verifyci.verification.semi_formal_reason import SemiFormalReasoner
DIFF_PREFIXED = "diff --git a/src/app.py b/src/app.py\n--- a/src/app.py\n+++ b/src/app.py\n@@ -10,2 +10,2 @@\n context\n-old\n+new\n"
DIFF_NOPREFIX = "diff --git src/app.py src/app.py\n--- src/app.py\n+++ src/app.py\n@@ -10,2 +10,2 @@\n context\n-old\n+new\n"
DIFF_PLAIN = "--- src/app.py\n+++ src/app.py\n@@ -10,2 +10,2 @@\n context\n-old\n+new\n"
def _payload():
    return SimpleNamespace(revision_entity_id="e1", logical_entity_id="logical:e1", name="func", file_path="src/app.py", line_start=10, line_end=20, source_hash="abc123")
class FakeGraph:
    def __init__(self, payloads):
        self._payloads = payloads
    def nodes(self):
        return list(self._payloads)
    def node_indices(self):
        return list(range(len(self._payloads)))
    def predecessors(self, idx):
        return []
    def successors(self, idx):
        return []
def test_noprefix_parse_parity():
    assert parse_diff_files(DIFF_PREFIXED) == parse_diff_files(DIFF_NOPREFIX)
    assert parse_diff_files(DIFF_NOPREFIX) == ["src/app.py"]
    assert parse_diff_files(DIFF_PLAIN) == ["src/app.py"]
def test_noprefix_no_stray():
    assert unattributed_removed_lines(DIFF_PREFIXED) == []
    assert unattributed_removed_lines(DIFF_NOPREFIX) == []
    assert unattributed_removed_lines(DIFF_PLAIN) == []
    assert find_deletion_hunks(DIFF_PREFIXED) == []
    assert find_deletion_hunks(DIFF_NOPREFIX) == []
    assert find_deletion_hunks(DIFF_PLAIN) == []
def test_noprefix_verify_parity():
    graph = FakeGraph([_payload()])
    c1 = SemiFormalReasoner().verify(DIFF_PREFIXED, graph)
    c2 = SemiFormalReasoner().verify(DIFF_NOPREFIX, graph)
    c3 = SemiFormalReasoner().verify(DIFF_PLAIN, graph)
    assert c1.certificate_verified == c2.certificate_verified
    assert c2.certificate_verified == c3.certificate_verified
