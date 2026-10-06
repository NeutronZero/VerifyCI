"""CAP-003A: Path-Sensitive Removal Provenance Test Suite.

Verifies:
- Path sensitivity & ambiguous suffix rejection
- Per-line provenance hashes for deep deletions (>2,000 chars)
- Nested scope & enclosing entity disambiguation
- Unicode NFC/NFD equivalence and homoglyph detection
- Tri-state verification: VERIFIED, FABRICATED, INCONCLUSIVE
- Invariant: absence of evidence is not evidence of absence (never false PASS)
"""
import hashlib
from types import SimpleNamespace
import unicodedata

from verifyci.verification.removal import (
    _path_matches,
    removal_provenance_check,
)


def _ent(start, end, snippet, path="src/app.py", type_=None, complete=True, line_hashes=None):
    meta = {}
    if snippet is not None:
        meta["snippet"] = snippet
        meta["snippet_is_complete"] = complete
    if line_hashes is not None:
        meta["line_hashes"] = line_hashes
    ns = SimpleNamespace(
        file_path=path,
        line_start=start,
        line_end=end,
        metadata=meta,
    )
    if type_ is not None:
        ns.type = type_
    return ns


def test_path_matching_rejects_bare_filename_against_qualified_path():
    # Diff touches app/models.py, entity is bare models.py
    assert _path_matches("app/models.py", "app/models.py") is True
    assert _path_matches("app/models.py", "core/models.py") is False
    assert _path_matches("app/models.py", "models.py") is False
    assert _path_matches("models.py", "app/models.py") is False
    assert _path_matches("oauth/tokens.py", "tokens.py") is False


def test_path_collision_routes_to_inconclusive_not_false_pass():
    # Diff deletes from app/models.py, but entity store only has models.py
    diff = (
        "diff --git a/app/models.py b/app/models.py\n"
        "--- a/app/models.py\n"
        "+++ b/app/models.py\n"
        "@@ -10,2 +10,1 @@\n"
        " def get_user(uid):\n"
        "-    return db.find(uid)\n"
    )
    ent = _ent(10, 11, "def get_user(uid):\n    return db.find(uid)\n", path="models.py")
    res = removal_provenance_check(diff, [ent])
    # Must NOT falsely verify models.py for app/models.py
    assert res.established is False
    assert res.passed is True
    assert "unverified" in res.explanation


def test_deep_deletion_verifies_via_line_hashes_when_snippet_truncated():
    # 70 lines (~2,600 chars). Snippet is truncated at line 30, but line_hashes covers all 70.
    lines = [f"    line_{i:02d} = compute({i})\n" for i in range(1, 71)]
    hashes = [hashlib.sha256(line_str.encode("utf-8")).hexdigest() for line_str in lines]
    truncated_snippet = "".join(lines[:25])  # only 25 lines stored in snippet

    ent = _ent(10, 79, truncated_snippet, path="src/worker.py", complete=False, line_hashes=hashes)

    # Diff removes lines 35-37 (beyond the snippet truncation point)
    diff_lines = [
        "diff --git a/src/worker.py b/src/worker.py\n",
        "--- a/src/worker.py\n",
        "+++ b/src/worker.py\n",
        "@@ -43,4 +43,1 @@\n",
        "     line_34 = compute(34)\n",
        "-    line_35 = compute(35)\n",
        "-    line_36 = compute(36)\n",
        "-    line_37 = compute(37)\n",
    ]
    diff = "".join(diff_lines)

    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is True
    assert "verified=3" in res.explanation


def test_deep_deletion_catches_fabrication_past_snippet_truncation():
    # Line 36 has fabricated content
    lines = [f"    line_{i:02d} = compute({i})\n" for i in range(1, 71)]
    hashes = [hashlib.sha256(line_str.encode("utf-8")).hexdigest() for line_str in lines]
    truncated_snippet = "".join(lines[:25])

    ent = _ent(10, 79, truncated_snippet, path="src/worker.py", complete=False, line_hashes=hashes)

    diff_lines = [
        "diff --git a/src/worker.py b/src/worker.py\n",
        "--- a/src/worker.py\n",
        "+++ b/src/worker.py\n",
        "@@ -43,4 +43,1 @@\n",
        "     line_34 = compute(34)\n",
        "-    line_35 = compute(35)\n",
        "-    line_36 = malicious_payload()\n",
        "-    line_37 = compute(37)\n",
    ]
    diff = "".join(diff_lines)

    res = removal_provenance_check(diff, [ent])
    assert res.passed is False
    assert res.established is True
    assert "src/worker.py:45" in res.evidence


def test_nested_function_removal_within_outer_class():
    class_code = (
        "class Controller:\n"
        "    def run(self):\n"
        "        pass\n"
        "    def handle(self):\n"
        "        return 1\n"
    )
    ent_class = _ent(1, 5, class_code, path="src/ctrl.py", type_="CLASS")
    ent_method = _ent(4, 5, "    def handle(self):\n        return 1\n", path="src/ctrl.py", type_="METHOD")

    diff = (
        "diff --git a/src/ctrl.py b/src/ctrl.py\n"
        "--- a/src/ctrl.py\n"
        "+++ b/src/ctrl.py\n"
        "@@ -3,3 +3,1 @@\n"
        "         pass\n"
        "-    def handle(self):\n"
        "-        return 1\n"
    )
    res = removal_provenance_check(diff, [ent_class, ent_method])
    assert res.passed is True
    assert res.established is True


def test_unicode_nfc_nfd_equivalence():
    nfc = "    résumé = True\n"
    nfd = "    " + unicodedata.normalize("NFD", "résumé") + " = True\n"

    ent = _ent(10, 11, f"def load():\n{nfc}", path="src/doc.py")
    diff = (
        "diff --git a/src/doc.py b/src/doc.py\n"
        "--- a/src/doc.py\n"
        "+++ b/src/doc.py\n"
        "@@ -10,2 +10,1 @@\n"
        " def load():\n"
        f"-{nfd}"
    )
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is True


def test_cyrillic_homoglyph_is_caught_as_fabricated():
    # Latin "data" in base, Cyrillic "а" in diff
    cyrillic_a = "\u0430"
    ent = _ent(10, 11, "def load():\n    data = 1\n", path="src/doc.py")
    diff = (
        "diff --git a/src/doc.py b/src/doc.py\n"
        "--- a/src/doc.py\n"
        "+++ b/src/doc.py\n"
        "@@ -10,2 +10,1 @@\n"
        " def load():\n"
        f"-    d{cyrillic_a}t{cyrillic_a} = 1\n"
    )
    res = removal_provenance_check(diff, [ent])
    assert res.passed is False
    assert res.established is True


def test_unmodeled_comment_is_inconclusive_never_pass_or_fail():
    ent = _ent(10, 20, "def run():\n    pass\n", path="src/app.py")
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,2 +1,1 @@\n"
        "-# copyright 2026\n"
        " import os\n"
    )
    res = removal_provenance_check(diff, [ent])
    assert res.passed is True
    assert res.established is False
    assert "outside entity spans" in res.explanation
