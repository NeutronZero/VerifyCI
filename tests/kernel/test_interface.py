"""Tests for CLI, SARIF exporter, and FastMCP daemon."""

from __future__ import annotations

import json
from pathlib import Path

from verifyci.contracts.attestation import CanonicalAttestationPayload, VerificationCertificate
from verifyci.contracts.verdict import FindingReason, Severity, VerificationFinding, VerificationVerdict
from verifyci.interface.cli import main
from verifyci.interface.fastmcp_daemon import handle_verify_request
from verifyci.interface.sarif_exporter import certificate_to_sarif


def test_sarif_export_schema() -> None:
    finding = VerificationFinding(
        finding_id="f100",
        rule_id="VC-SECURITY-DANGEROUS-CALL",
        severity=Severity.HIGH,
        verdict=VerificationVerdict.FAIL,
        reason=FindingReason.DANGEROUS_CALL,
        message="eval call detected",
        file_path="src/exec.py",
        start_line=15,
        end_line=15,
    )
    payload = CanonicalAttestationPayload(
        base_commit_sha="c1",
        head_commit_sha="c2",
        files=("src/exec.py",),
        policy_hash="p1",
        verdict=VerificationVerdict.FAIL,
        findings=(finding,),
    )
    cert = VerificationCertificate(
        digest="digest123",
        digest_algorithm="sha256",
        verdict=VerificationVerdict.FAIL,
        payload=payload,
        rationale="failed",
    )

    sarif = certificate_to_sarif(cert)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VerifyCI"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "VC-SECURITY-DANGEROUS-CALL"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 15


def test_cli_verify_diff_clean_pass(tmp_path: Path) -> None:
    patch_file = tmp_path / "clean.patch"
    patch_content = (
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,2 +1,3 @@\n"
        " def run():\n"
        "+    # benign addition\n"
        "     return 42\n"
    )
    patch_file.write_text(patch_content, encoding="utf-8")

    exit_code = main(["verify-diff", "-d", str(patch_file)])
    assert exit_code == 0


def test_cli_verify_diff_secret_fail(tmp_path: Path) -> None:
    patch_file = tmp_path / "secret.patch"
    patch_content = (
        "--- a/src/auth.py\n"
        "+++ b/src/auth.py\n"
        "@@ -1,1 +1,2 @@\n"
        "+ghp_1234567890abcdef1234567890abcdef1234\n"
        " pass\n"
    )
    patch_file.write_text(patch_content, encoding="utf-8")

    exit_code = main(["verify-diff", "-d", str(patch_file)])
    assert exit_code == 1


def test_cli_verify_diff_ungrounded_inconclusive(tmp_path: Path) -> None:
    patch_file = tmp_path / "ungrounded.patch"
    patch_content = (
        "--- a/src/data.py\n"
        "+++ b/src/data.py\n"
        "@@ -1,5 +1,1 @@\n"
        "-line1\n"
        "-line2\n"
        "-line3\n"
        "+line_new\n"
    )
    patch_file.write_text(patch_content, encoding="utf-8")

    exit_code = main(["verify-diff", "-d", str(patch_file)])
    assert exit_code == 2


def test_cli_sarif_output_to_file(tmp_path: Path) -> None:
    patch_file = tmp_path / "clean.patch"
    patch_file.write_text("--- a/src/x.py\n+++ b/src/x.py\n@@ -1 +1 @@\n+a = 1\n", encoding="utf-8")
    out_file = tmp_path / "results.sarif"

    exit_code = main(["verify-diff", "-d", str(patch_file), "-f", "sarif", "-o", str(out_file)])
    assert exit_code == 0
    assert out_file.is_file()

    sarif_data = json.loads(out_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"


def test_fastmcp_handle_verify_request() -> None:
    res = handle_verify_request(
        file_path="src/service.py",
        base_source="def hello(): return 'world'\n",
        head_source="def hello(): return 'world'  # greeting\n",
    )
    assert res["verdict"] == "PASS"
    assert "digest" in res
