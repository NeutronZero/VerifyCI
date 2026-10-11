import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from fastapi import HTTPException

from verifyci.contracts.verification_ir import VerificationPolicy
from verifyci.interface.commands.verify import run_verify
from verifyci.interface.http import HTTPBackpressure
from verifyci.interface.ingress import (
    IngressValidationError,
    validate_diff_complexity,
    validate_diff_ingress,
)
from verifyci.interface.limits import (
    MAX_CHANGED_FILES,
    MAX_CHANGED_LINES,
    ExecutionBudget,
)


def test_diff_complexity_file_cap():
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
    # An already-expired budget deadline causes immediate INFRA_ERROR
    expired_budget = ExecutionBudget(deadline_monotonic=time.monotonic() - 1.0)
    diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    res = run_verify(diff, budget=expired_budget)
    assert res["status"] == "INFRA_ERROR"
    assert res["error"] == "timeout"
    assert "verification_budget_deadline_exceeded" in res["rationale"]


def test_http_backpressure_queue_rejection_429():
    bp = HTTPBackpressure(max_workers=2, max_queue=2)
    # Total capacity = 2 + 2 = 4
    bp.active_and_queued = 4
    with pytest.raises(HTTPException) as exc:
        with bp.guard():
            pass
    assert exc.value.status_code == 429
    assert "max worker queue depth exceeded" in exc.value.detail


def test_run_verify_envelope_and_signature():
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
    res = run_verify(diff, signing_key=priv_key, return_artifacts=True)
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


def test_run_verify_advisory_policy_produces_advisory_warn():
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
    res = run_verify(diff, policy=advisory_policy, return_artifacts=True)
    assert res["status"] == "ADVISORY_WARN"
    env = res.get("envelope")
    assert env is not None
    assert env.verdict == "ADVISORY_WARN"

