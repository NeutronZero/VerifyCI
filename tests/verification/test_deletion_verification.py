from verifyci.contracts.entity import Entity, EntityType
from verifyci.contracts.verification_ir import SignedIntentWaiver
from verifyci.verification.deletion import (
    DeletionClass,
    verify_deletion_hunks,
)
from verifyci.verification.semi_formal_reason import SemiFormalReasoner


class MockGraph:
    def __init__(self, nodes, calls=None):
        self._nodes = nodes
        self._calls = calls or {}
        self._rcalls = {}
        for src, dsts in self._calls.items():
            for dst in dsts:
                self._rcalls.setdefault(dst, []).append(src)

    def nodes(self):
        return list(self._nodes)

    def node_indices(self):
        return list(range(len(self._nodes)))

    def predecessors(self, idx):
        return list(self._rcalls.get(idx, []))

    def successors(self, idx):
        return list(self._calls.get(idx, []))


def _mock_func_entity(
    name: str = "f",
    file_path: str = "src/app.py",
    rev_id: str = "e1",
    start: int = 10,
    end: int = 15,
    snippet: str | None = None,
):
    if snippet is None:
        snippet = f"def {name}():\n    return 42\n"
    return Entity(
        repository_id="repo",
        logical_entity_id=f"log_{name}",
        revision_entity_id=rev_id,
        type=EntityType.FUNCTION,
        name=name,
        file_path=file_path,
        line_start=start,
        line_end=end,
        language="python",
        source_hash="hash1",
        revision_id="rev1",
        metadata={
            "snippet": snippet,
            "snippet_is_complete": True,
        },
    )


# ---------------------------------------------------------------------------
# 1. Genuine Dead Code Deletion (Class 1 PASS)
# ---------------------------------------------------------------------------


def test_genuine_dead_code_deletion_passes():
    # Helper func 'unused_helper' has 0 incoming callers and is completely deleted
    ent_helper = _mock_func_entity(
        name="unused_helper",
        file_path="src/app.py",
        rev_id="e_helper",
        start=10,
        end=12,
        snippet="def unused_helper():\n    return 1\n",
    )
    ent_main = _mock_func_entity(
        name="main_func",
        file_path="src/app.py",
        rev_id="e_main",
        start=15,
        end=20,
        snippet="def main_func():\n    return 2\n",
    )
    # Graph has no incoming edges to unused_helper (predecessors=0)
    graph = MockGraph([ent_helper, ent_main], calls={})
    node_map = {"e_helper": 0, "e_main": 1}

    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,0 @@\n"
        "-def unused_helper():\n"
        "-    return 1\n"
        "-\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent_helper, ent_main],
    )

    assert cert.conclusion.result == "pass"
    assert cert.certificate_verified is True


# ---------------------------------------------------------------------------
# 2. Deletion with Surviving Caller (Class 1 DECLINES)
# ---------------------------------------------------------------------------


def test_dead_code_deletion_with_surviving_caller_declines():
    # Helper func is deleted, but 'surviving_caller' still has an edge calling it
    ent_callee = _mock_func_entity(
        name="callee",
        file_path="src/app.py",
        rev_id="e_callee",
        start=10,
        end=12,
        snippet="def callee():\n    return 1\n",
    )
    ent_caller = _mock_func_entity(
        name="surviving_caller",
        file_path="src/other.py",
        rev_id="e_caller",
        start=10,
        end=15,
        snippet="def surviving_caller():\n    return callee()\n",
    )
    # Edge: caller (1) -> callee (0)
    graph = MockGraph([ent_callee, ent_caller], calls={1: [0]})
    node_map = {"e_callee": 0, "e_caller": 1}

    # Diff only deletes callee, leaving surviving_caller unedited!
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,0 @@\n"
        "-def callee():\n"
        "-    return 1\n"
        "-\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent_callee, ent_caller],
    )

    assert cert.conclusion.result != "pass"
    assert cert.certificate_verified is False
    assert "surviving_caller" in cert.conclusion.reasoning or "deletion" in cert.conclusion.reasoning


# ---------------------------------------------------------------------------
# 3. Incomplete / Missing Provenance (INCONCLUSIVE)
# ---------------------------------------------------------------------------


def test_incomplete_or_missing_provenance_is_inconclusive():
    # Entity has truncated snippet (is_complete=False)
    ent = _mock_func_entity(
        name="big_func",
        file_path="src/app.py",
        rev_id="e1",
        start=10,
        end=30,
        snippet="def big_func():\n    line1\n",
    )
    ent.metadata["snippet_is_complete"] = False
    ent.metadata["snippet_truncated_at_line"] = 12
    graph = MockGraph([ent])
    node_map = {"e1": 0}

    # Removing line 25 where snippet was truncated
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -24,2 +24,1 @@\n"
        "-    line_unknown = 99\n"
        "+    line_new = 100\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent],
    )

    assert cert.conclusion.result == "inconclusive"
    assert cert.certificate_verified is False


# ---------------------------------------------------------------------------
# 4. Fabricated Deletion Provenance (FAIL)
# ---------------------------------------------------------------------------


def test_fabricated_deletion_provenance_fails():
    ent = _mock_func_entity(
        name="f",
        file_path="src/app.py",
        rev_id="e1",
        start=10,
        end=12,
        snippet="def f():\n    return 1\n",
    )
    graph = MockGraph([ent])
    node_map = {"e1": 0}

    # Claiming to delete a line that contradicts stored content
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,2 +10,1 @@\n"
        "-def f():\n"
        "-    fabricated_call()\n"
        "+def f():\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent],
    )

    assert cert.conclusion.result == "fail"
    assert cert.certificate_verified is False


# ---------------------------------------------------------------------------
# 5. Entity Continuity Failure (DECLINES)
# ---------------------------------------------------------------------------


def test_entity_continuity_failure_declines():
    # Function is destroyed / changed to completely different entity
    ent = _mock_func_entity(
        name="worker",
        file_path="src/app.py",
        rev_id="e1",
        start=10,
        end=15,
        snippet="def worker():\n    do_work()\n",
    )
    # Caller in other file depends on worker
    caller = _mock_func_entity(
        name="caller",
        file_path="src/main.py",
        rev_id="e2",
        start=1,
        end=5,
        snippet="def caller():\n    worker()\n",
    )
    graph = MockGraph([ent, caller], calls={1: [0]})
    node_map = {"e1": 0, "e2": 1}

    # Def worker is deleted and replaced with unrelated variable
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,1 @@\n"
        "-def worker():\n"
        "-    do_work()\n"
        "+STATUS = 'idle'\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent, caller],
    )

    assert cert.conclusion.result != "pass"
    assert cert.certificate_verified is False


# ---------------------------------------------------------------------------
# 6. Signature Incompatibility (DECLINES)
# ---------------------------------------------------------------------------


def test_signature_incompatibility_declines():
    # func takes (x, y); callers supply two arguments
    ent = _mock_func_entity(
        name="compute",
        file_path="src/app.py",
        rev_id="e1",
        start=10,
        end=15,
        snippet="def compute(x, y):\n    return x + y\n",
    )
    caller = _mock_func_entity(
        name="caller",
        file_path="src/client.py",
        rev_id="e2",
        start=1,
        end=5,
        snippet="def caller():\n    return compute(1, 2)\n",
    )
    graph = MockGraph([ent, caller], calls={1: [0]})
    node_map = {"e1": 0, "e2": 1}

    # Diff removes parameter y and adds required parameter z with no default
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,2 +10,2 @@\n"
        "-def compute(x, y):\n"
        "-    return x + y\n"
        "+def compute(x, z, extra_req):\n"
        "+    return x + z + extra_req\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent, caller],
    )

    assert cert.conclusion.result != "pass"
    assert cert.certificate_verified is False


# ---------------------------------------------------------------------------
# 7. Valid Class 2 Refactoring with Execution Witness (PASS)
# ---------------------------------------------------------------------------


def test_valid_class_2_refactoring_with_execution_witness_passes():
    snippet = "def transform(data):\n    old_step()\n    return data\n"
    ent = _mock_func_entity(
        name="transform",
        file_path="src/app.py",
        rev_id="e1",
        start=10,
        end=13,
        snippet=snippet,
    )
    graph = MockGraph([ent])
    node_map = {"e1": 0}

    # Diff refactors internal implementation of transform and adds test witness
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -10,3 +10,3 @@\n"
        " def transform(data):\n"
        "-    old_step()\n"
        "+    new_step()\n"
        "     return data\n"
        "diff --git a/tests/test_app.py b/tests/test_app.py\n"
        "--- a/tests/test_app.py\n"
        "+++ b/tests/test_app.py\n"
        "@@ -1,0 +1,3 @@\n"
        "+def test_transform():\n"
        "+    from app import transform\n"
        "+    assert transform([1]) == [1]\n"
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent],
    )

    assert cert.conclusion.result == "pass"
    assert cert.certificate_verified is True
    assert len(cert.witnesses) >= 1


# ---------------------------------------------------------------------------
# 8. Class 3 Guard Deletion Without Waiver (FAILS CLOSED)
# ---------------------------------------------------------------------------


def test_class_3_security_guard_deletion_without_waiver_fails_closed():
    snippet = "def transfer(amount):\n    assert amount > 0\n    return amount\n"
    ent = _mock_func_entity(
        name="transfer",
        file_path="src/bank.py",
        rev_id="e1",
        start=10,
        end=13,
        snippet=snippet,
    )
    graph = MockGraph([ent])
    node_map = {"e1": 0}

    # Diff deletes the assert guard!
    diff = (
        "diff --git a/src/bank.py b/src/bank.py\n"
        "--- a/src/bank.py\n"
        "+++ b/src/bank.py\n"
        "@@ -10,3 +10,2 @@\n"
        " def transfer(amount):\n"
        "-    assert amount > 0\n"
        "     return amount\n"
        "diff --git a/tests/test_bank.py b/tests/test_bank.py\n"
        "--- a/tests/test_bank.py\n"
        "+++ b/tests/test_bank.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_transfer():\n"
        "+    assert transfer(5) == 5\n"
    )

    reasoner = SemiFormalReasoner()
    # Even though tests are added, guard deletion without waiver MUST fail closed!
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent],
    )

    assert cert.conclusion.result == "fail"
    assert cert.certificate_verified is False
    assert "class_3" in cert.conclusion.reasoning or "guard" in cert.conclusion.reasoning


# ---------------------------------------------------------------------------
# 9. Class 3 Guard Deletion With Valid Signed Waiver (PASS)
# ---------------------------------------------------------------------------


def test_class_3_guard_deletion_with_valid_waiver_passes(monkeypatch):
    import hashlib
    import hmac
    monkeypatch.setenv("VERIFYCI_WAIVER_KEYS", "test-key")
    snippet = "def transfer(amount):\n    assert amount > 0\n    return amount\n"
    ent = _mock_func_entity(
        name="transfer",
        file_path="src/bank.py",
        rev_id="e1",
        start=10,
        end=13,
        snippet=snippet,
    )
    graph = MockGraph([ent])
    node_map = {"e1": 0}

    diff = (
        "diff --git a/src/bank.py b/src/bank.py\n"
        "--- a/src/bank.py\n"
        "+++ b/src/bank.py\n"
        "@@ -10,3 +10,2 @@\n"
        " def transfer(amount):\n"
        "-    assert amount > 0\n"
        "     return amount\n"
        "diff --git a/tests/test_bank.py b/tests/test_bank.py\n"
        "--- a/tests/test_bank.py\n"
        "+++ b/tests/test_bank.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def test_transfer():\n"
        "+    assert transfer(5) == 5\n"
    )

    # Keyed HMAC waiver: proves the cryptographic path end to end
    # (deny-by-default means a made-up signature no longer passes).
    waiver_id, target = "waiver-001", "assert amount > 0"
    canonical = (f"{waiver_id}:{target}:security_admin:"
                 "Intentional deprecation of assertion in favor of external gateway")
    waiver = SignedIntentWaiver(
        waiver_id=waiver_id,
        target=target,
        signer="security_admin",
        signature=hmac.new(b"test-key", canonical.encode("utf-8"),
                           hashlib.sha256).hexdigest(),
        reason="Intentional deprecation of assertion in favor of external gateway",
        valid=True,
    )

    reasoner = SemiFormalReasoner()
    cert = reasoner.verify(
        diff=diff,
        graph=graph,
        node_map=node_map,
        entities=[ent],
        waivers=[waiver],
    )

    assert cert.conclusion.result == "pass"
    assert cert.certificate_verified is True


def test_class_3_unverifiable_waiver_does_not_suppress(monkeypatch):
    # Deny by default at the matching layer: a made-up signature with
    # no keys configured must NOT waive the guard-removal FAIL, and a
    # wildcard target must not match everything either.
    from verifyci.verification.deletion import _matches_waiver
    monkeypatch.delenv("VERIFYCI_WAIVER_KEYS", raising=False)
    monkeypatch.delenv("VERIFYCI_WAIVER_ALLOW_UNAUTHENTICATED", raising=False)
    fake = SignedIntentWaiver(
        waiver_id="w-x", target="assert amount > 0", signer="mallory",
        signature="made-up", reason="trust me", valid=True)
    assert _matches_waiver(["assert amount > 0"], "src/bank.py", [fake]) is None
    wild = SignedIntentWaiver(
        waiver_id="w-y", target="*", signer="mallory",
        signature="made-up", reason="trust me", valid=True)
    assert _matches_waiver(["assert amount > 0"], "src/bank.py", [wild]) is None


# ---------------------------------------------------------------------------
# 10. Direct Deletion Classification Unit Tests
# ---------------------------------------------------------------------------


def test_verify_deletion_hunks_classification():
    diff_c1 = (
        "diff --git a/src/dead.py b/src/dead.py\n"
        "--- a/src/dead.py\n"
        "+++ b/src/dead.py\n"
        "@@ -1,3 +1,0 @@\n"
        "-def dead():\n"
        "-    pass\n"
        "-\n"
    )
    ent_dead = _mock_func_entity(name="dead", file_path="src/dead.py", start=1, end=3, snippet="def dead():\n    pass\n")
    graph = MockGraph([ent_dead])
    node_map = {"e1": 0}

    verdicts = verify_deletion_hunks(
        diff=diff_c1,
        code_files=["src/dead.py"],
        entities=[ent_dead],
        graph=graph,
        node_map=node_map,
    )
    assert len(verdicts) == 1
    assert verdicts[0].deletion_class == DeletionClass.CLASS_1_DEAD_CODE
    assert verdicts[0].passed is True
