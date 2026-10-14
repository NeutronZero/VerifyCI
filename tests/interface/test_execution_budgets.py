import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from fastapi import HTTPException

# NOTE: verifyci imports stay function-level in this file. The test runner's
# system interpreter carries C:\Projects\verifyci on sys.path; top-level
# imports would bind that stale checkout at collection time and poison
# sys.modules for every other gate file in the same pytest process.


def test_diff_complexity_file_cap():
    from verifyci.interface.commands.verify import run_verify
    from verifyci.interface.ingress import (
        IngressValidationError,
        validate_diff_complexity,
        validate_diff_ingress,
    )
    from verifyci.interface.limits import MAX_CHANGED_FILES
    # Diff touching 201 files exceeds MAX_CHANGED_FILES (200)
    files = [f"file_{i}.py" for i in range(MAX_CHANGED_FILES + 1)]
    diff_parts = []
    for f in files:
        diff_parts.append(f"diff --git a/{f} b/{f}\n--- a/{f}\n+++ b/{f}\n@@ -1,1 +1,1 @@\n-a\n+b\n")
    huge_diff = "".join(diff_parts)

    with pytest.raises(IngressValidationError) as exc:
        validate_diff_complexity(huge_diff)
    assert exc.value.code == "diff_too_many_files"

    # Also verify validate_diff_ingress fails closed
    with pytest.raises(IngressValidationError) as exc:
        validate_diff_ingress(huge_diff)
    assert exc.value.code == "diff_too_many_files"

    # run_verify routes ingress refusal to INFRA_ERROR (exit code 3 equivalent)
    res = run_verify(huge_diff)
    assert res["status"] == "INFRA_ERROR"
    assert res["error"] == "diff_too_many_files"
    assert "ingress_refusal:diff_too_many_files" in res["rationale"]


def test_diff_complexity_line_cap():
    from verifyci.interface.commands.verify import run_verify
    from verifyci.interface.ingress import (
        IngressValidationError,
        validate_diff_complexity,
        validate_diff_ingress,
    )
    from verifyci.interface.limits import MAX_CHANGED_LINES
    # Diff with 1 file but >10,000 modified lines
    header = "diff --git a/big.py b/big.py\n--- a/big.py\n+++ b/big.py\n@@ -1,10005 +1,10005 @@\n"
    lines = ["+line\n"] * (MAX_CHANGED_LINES + 5)
    huge_diff = header + "".join(lines)

    with pytest.raises(IngressValidationError) as exc:
        validate_diff_complexity(huge_diff)
    assert exc.value.code == "diff_too_many_lines"

    with pytest.raises(IngressValidationError) as exc:
        validate_diff_ingress(huge_diff)
    assert exc.value.code == "diff_too_many_lines"

    res = run_verify(huge_diff)
    assert res["status"] == "INFRA_ERROR"
    assert res["error"] == "diff_too_many_lines"
    assert "ingress_refusal:diff_too_many_lines" in res["rationale"]


def test_execution_budget_deadline_expired_fail_closed():
    from verifyci.interface.commands.verify import run_verify
    from verifyci.interface.limits import ExecutionBudget
    # An already-expired budget deadline causes immediate INFRA_ERROR
    expired_budget = ExecutionBudget(deadline_monotonic=time.monotonic() - 1.0)
    diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    res = run_verify(diff, budget=expired_budget)
    assert res["status"] == "INFRA_ERROR"
    assert res["error"] == "timeout"
    assert "verification_budget_deadline_exceeded" in res["rationale"]


def test_http_backpressure_queue_rejection_429():
    from verifyci.interface.http import HTTPBackpressure
    bp = HTTPBackpressure(max_workers=2, max_queue=2)
    # Total capacity = 2 + 2 = 4
    bp.active_and_queued = 4
    with pytest.raises(HTTPException) as exc:
        with bp.guard():
            pass
    assert exc.value.status_code == 429
    assert "max worker queue depth exceeded" in exc.value.detail


def test_run_verify_envelope_and_signature(tmp_path):
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "valid.db")
    GraphStore(db).close()

    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-old doc\n"
        "+new doc\n"
    )
    res = run_verify(diff, db_path=db, signing_key=priv_key, return_artifacts=True)
    assert res["status"] == "HUMAN_REVIEW"
    env = res.get("envelope")
    assert env is not None
    assert env.signature is not None
    assert env.signing_key_id is not None
    assert env.verdict == "HUMAN_REVIEW"
    assert env.report_id == res["report"].report_id
    assert env.report_hash != ""
    assert env.effective_policy_bundle_hash != ""
    assert len(env.check_summaries) > 0
    # Signature must verify against author public key
    assert env.verify_signature(public_key=pub_key) is True


def test_run_verify_advisory_policy_produces_advisory_warn(tmp_path):
    from verifyci.contracts.verification_ir import VerificationPolicy
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "valid.db")
    GraphStore(db).close()

    # Non-blocking failure under advisory policy yields ADVISORY_WARN (exit 2), never PASS (0)
    diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-old doc\n"
        "+new doc\n"
    )
    advisory_policy = VerificationPolicy.advisory(policy_id="test_advisory")
    res = run_verify(diff, db_path=db, policy=advisory_policy, return_artifacts=True)
    assert res["status"] == "ADVISORY_WARN"
    env = res.get("envelope")
    assert env is not None
    assert env.verdict == "ADVISORY_WARN"


def test_signing_failure_is_fail_closed_infra_error(tmp_path, monkeypatch):
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "valid.db")
    GraphStore(db).close()

    diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-old doc\n"
        "+new doc\n"
    )
    # Pass an invalid signing key that causes signing to raise
    res = run_verify(diff, db_path=db, signing_key="invalid_raw_key_string")
    assert res["status"] == "INFRA_ERROR"
    assert res["error"] == "signing_failed"
    assert "envelope_signing_failed" in res["rationale"]
    assert res["envelope"] is None


def test_require_signed_envelope_policy_rejects_unsigned_result(tmp_path):
    from verifyci.contracts.verification_ir import VerificationPolicy
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "valid.db")
    GraphStore(db).close()

    diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-old doc\n"
        "+new doc\n"
    )
    policy = VerificationPolicy.strict_gate(
        policy_id="strict_signed",
        require_signed_envelope=True,
    )
    # Verification executed without signing key must fail-closed as INFRA_ERROR
    res = run_verify(diff, db_path=db, policy=policy)
    assert res["status"] == "INFRA_ERROR"
    assert res["error"] == "signing_failed"
    assert "envelope_signing_failed" in res["rationale"]
    assert res["envelope"] is None


def test_envelope_sign_exception_fails_closed_infra_error(tmp_path, monkeypatch):
    """Specifically test that an exception raised inside envelope.sign() fails closed as INFRA_ERROR."""
    from verifyci.contracts.verification_ir import VerificationEnvelope
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore

    db = str(tmp_path / "valid.db")
    GraphStore(db).close()

    priv = Ed25519PrivateKey.generate()
    diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-old doc\n"
        "+new doc\n"
    )

    def _failing_sign(self, *args, **kwargs):
        raise RuntimeError("hsm_offline_error")

    monkeypatch.setattr(VerificationEnvelope, "sign", _failing_sign)
    res = run_verify(diff, db_path=db, signing_key=priv)
    assert res["status"] == "INFRA_ERROR"
    assert res["error"] == "signing_failed"
    assert "envelope_signing_failed:hsm_offline_error" in res["rationale"]
    assert res["envelope"] is None


def test_require_signed_envelope_trust_verification_lifecycle(tmp_path):
    """Test require_signed_envelope rejects untrusted signers and accepts authorized trust store signers."""
    from verifyci.contracts.verification_ir import VerificationPolicy
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore

    db = str(tmp_path / "valid.db")
    GraphStore(db).close()

    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    other_pub_hex = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()

    diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-old doc\n"
        "+new doc\n"
    )
    policy = VerificationPolicy.strict_gate(
        policy_id="strict_signed",
        require_signed_envelope=True,
    )

    # 1. Signer not in trust store -> fail closed as INFRA_ERROR with trust_verification_failed
    res_untrusted = run_verify(
        diff, db_path=db, signing_key=priv, policy=policy, trusted_keys=[other_pub_hex]
    )
    assert res_untrusted["status"] == "INFRA_ERROR"
    assert res_untrusted["error"] == "trust_verification_failed"
    assert "envelope_trust_verification_failed" in res_untrusted["rationale"]
    assert res_untrusted["envelope"] is None

    # 2. Signer authorized in trust store -> passes verification
    res_trusted = run_verify(
        diff, db_path=db, signing_key=priv, policy=policy, trusted_keys=[pub_hex]
    )
    assert res_trusted["status"] == "HUMAN_REVIEW"
    assert res_trusted["envelope"] is not None
    assert res_trusted["envelope"].signature is not None
    assert res_trusted["envelope"].verify_signature(trusted_keys=[pub_hex]) is True


def test_source_commit_id_distinction_from_revision_id(tmp_path):
    """Test that source_commit_id is resolved from authoritative ingest records and never substituted with revision_id."""
    import time
    from verifyci.contracts.revision import Revision
    from verifyci.interface.commands.verify import run_verify
    from verifyci.storage.graph_store import GraphStore

    db = str(tmp_path / "lineage.db")
    store = GraphStore(db)

    # 1. Case: commit_id is known and recorded
    rev = Revision(
        revision_id="content_hash_rev_123",
        repository_id="repo_verifyci",
        commit_id="git_commit_sha_abc",
        parent_revision_id=None,
        source_hash="src_hash_1",
        timestamp=time.time(),
        ingestion_config_hash="cfg_hash_1",
    )
    store.insert_revision(rev)
    store.close()

    diff = (
        "diff --git a/docs/README.md b/docs/README.md\n"
        "--- a/docs/README.md\n"
        "+++ b/docs/README.md\n"
        "@@ -1,1 +1,1 @@\n"
        "-old doc\n"
        "+new doc\n"
    )
    res = run_verify(diff, db_path=db, revision_id="content_hash_rev_123")
    assert res["envelope"] is not None
    assert res["envelope"].revision_id == "content_hash_rev_123"
    assert res["envelope"].source_commit_id == "git_commit_sha_abc"
    assert res["envelope"].source_commit_id != res["envelope"].revision_id

    # 2. Case: commit_id is unknown/unrecorded -> represented as "", NEVER substituted with revision_id
    db2 = str(tmp_path / "no_commit.db")
    store2 = GraphStore(db2)
    rev2 = Revision(
        revision_id="content_hash_rev_456",
        repository_id="repo_verifyci",
        commit_id=None,
        parent_revision_id=None,
        source_hash="src_hash_2",
        timestamp=time.time(),
        ingestion_config_hash="cfg_hash_2",
    )
    store2.insert_revision(rev2)
    store2.close()

    res2 = run_verify(diff, db_path=db2, revision_id="content_hash_rev_456")
    assert res2["envelope"] is not None
    assert res2["envelope"].revision_id == "content_hash_rev_456"
    assert res2["envelope"].source_commit_id == ""
    assert res2["envelope"].source_commit_id != res2["envelope"].revision_id


def test_sarif_export_handles_advisory_warn():
    from verifyci.export.sarif import export_sarif
    res = {
        "report_id": "rep_123",
        "status": "ADVISORY_WARN",
        "rationale": "non-blocking advisory finding in docs",
        "revision_id": "rev_abc",
        "files": ["docs/README.md"],
    }
    sarif_str = export_sarif(res)
    import json
    data = json.loads(sarif_str)
    assert data["runs"][0]["invocations"][0]["properties"]["verdict"] == "ADVISORY_WARN"
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "advisory_warning"
    assert results[0]["level"] == "warning"
    assert results[0]["kind"] == "review"
    assert results[0]["properties"]["verdict"] == "ADVISORY_WARN"


def test_multi_seed_traversal_budget_accumulation():
    import rustworkx as rx
    from verifyci.graph.traverse import (
        TraversalBudgetExceededError,
        traverse,
    )
    from verifyci.interface.limits import ExecutionBudget

    g = rx.PyDiGraph()
    n0 = g.add_node({"revision_entity_id": "seed0"})
    n1 = g.add_node({"revision_entity_id": "n1"})
    n2 = g.add_node({"revision_entity_id": "seed1"})
    n3 = g.add_node({"revision_entity_id": "n3"})
    g.add_edge(n0, n1, {"type": "CALLS"})
    g.add_edge(n2, n3, {"type": "CALLS"})
    nmap = {"seed0": n0, "n1": n1, "seed1": n2, "n3": n3}

    # Budget with max 1 edge traversal allowed
    b = ExecutionBudget.create(timeout_seconds=10.0, max_edges=1)
    # First traversal consumes 1 edge
    res1 = traverse(g, n0, direction="outgoing", max_hops=1, node_map=nmap, budget=b)
    assert res1 == {n1}
    assert b.edges_visited == 1

    # Second traversal on same shared budget accumulates and must fail closed
    with pytest.raises(TraversalBudgetExceededError):
        traverse(g, n2, direction="outgoing", max_hops=1, node_map=nmap, budget=b)


def test_http_verify_concurrent_backpressure_429():
    from fastapi.testclient import TestClient
    from verifyci.interface.http import GLOBAL_HTTP_BACKPRESSURE, app

    # Provide loopback client host
    client = TestClient(app, client=("127.0.0.1", 50000))
    # Artificially saturate backpressure
    original = GLOBAL_HTTP_BACKPRESSURE.active_and_queued
    try:
        GLOBAL_HTTP_BACKPRESSURE.active_and_queued = (
            GLOBAL_HTTP_BACKPRESSURE.max_workers + GLOBAL_HTTP_BACKPRESSURE.max_queue
        )
        response = client.post("/verify/diff", json={"diff": "diff --git a/a.py b/a.py\n"})
        assert response.status_code == 429
        assert "Server overloaded" in response.json()["detail"]
    finally:
        GLOBAL_HTTP_BACKPRESSURE.active_and_queued = original


def test_unusual_unified_diff_formats_grounding():
    from verifyci.verification.diffmap import GroundingStatus, parse_unified_diff

    # 1. /dev/null deletion
    diff_del = (
        "diff --git a/deleted.py b/deleted.py\n"
        "deleted file mode 100644\n"
        "--- a/deleted.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-line1\n"
        "-line2\n"
    )
    res_del = parse_unified_diff(diff_del)
    assert len(res_del) == 1
    assert res_del[0].path == "deleted.py"
    assert res_del[0].grounding_status == GroundingStatus.TEXT

    # 2. File rename with similarity index
    diff_rename = (
        "diff --git a/old_name.py b/new_name.py\n"
        "similarity index 100%\n"
        "rename from old_name.py\n"
        "rename to new_name.py\n"
    )
    res_rename = parse_unified_diff(diff_rename)
    assert len(res_rename) == 1
    assert res_rename[0].path == "new_name.py"

    # 3. Mode change only
    diff_mode = (
        "diff --git a/run.sh b/run.sh\n"
        "old mode 100644\n"
        "new mode 100755\n"
    )
    res_mode = parse_unified_diff(diff_mode)
    assert len(res_mode) == 1
    assert res_mode[0].grounding_status == GroundingStatus.MODE_ONLY



