"""Test protecting the external-adopter package contract and CLI user workflow."""
from __future__ import annotations

import json
from pathlib import Path
from typer.testing import CliRunner

from verifyci.interface.cli import app
from verifyci.export.json import export_certificate_json
from verifyci.export.sarif import export_sarif
from verifyci.secrets.redaction import assert_no_secret_leak


def test_package_exports_and_entrypoint():
    """Verify that all public package modules and entrypoints exist."""
    import verifyci
    import verifyci.contracts
    import verifyci.export
    import verifyci.interface.cli
    import verifyci.storage
    import verifyci.verification

    assert hasattr(verifyci.interface.cli, "app")
    assert callable(export_certificate_json)
    assert callable(export_sarif)


def test_adopter_cli_end_to_end(tmp_path: Path):
    """Simulate an external adopter initializing, ingesting, and verifying diffs."""
    runner = CliRunner()

    # 1. Base code with caller and callee
    billing_file = tmp_path / "billing.py"
    billing_file.write_text(
        "def compute_tax(subtotal: float) -> float:\n"
        "    return subtotal * 0.10\n\n"
        "def checkout(subtotal: float) -> float:\n"
        "    tax = compute_tax(subtotal)\n"
        "    return subtotal + tax\n",
        encoding="utf-8",
    )

    # 2. verifyci init & ingest
    res_init = runner.invoke(app, ["init", str(tmp_path)])
    assert res_init.exit_code == 0
    assert "Initialized VerifyCI" in res_init.output

    res_ingest = runner.invoke(app, ["ingest", str(tmp_path)])
    assert res_ingest.exit_code == 0
    assert "Revision:" in res_ingest.output

    db_path = str(tmp_path / ".verifyci" / "verifyci.db")
    res_stats = runner.invoke(app, ["stats", "--db", db_path])
    assert res_stats.exit_code == 0
    assert "entities:" in res_stats.output

    # 3. Add project invariant
    inv_file = tmp_path / ".verifyci" / "invariants.yaml"
    inv_file.write_text(
        "invariants:\n"
        "  - id: no_eval\n"
        "    rule: Disallow eval\n"
        "    query: forbid_call:eval\n"
        "    blocking: true\n",
        encoding="utf-8",
    )

    # 4. Clean diff adding helper -> PASS (exit 0)
    clean_diff = (
        "diff --git a/billing.py b/billing.py\n"
        "--- a/billing.py\n"
        "+++ b/billing.py\n"
        "@@ -4,3 +4,6 @@\n"
        " def checkout(subtotal: float) -> float:\n"
        "     tax = compute_tax(subtotal)\n"
        "     return subtotal + tax\n"
        "+\n"
        "+def apply_discount(subtotal: float) -> float:\n"
        "+    return compute_tax(subtotal) * 0.5\n"
    )
    res_pass = runner.invoke(app, ["verify-diff", clean_diff, "--db", db_path])
    assert res_pass.exit_code == 0, f"Expected PASS (0), got {res_pass.exit_code}: {res_pass.output}"
    assert "PASS" in res_pass.output

    # 5. JSON export validation
    json_out = str(tmp_path / "cert.json")
    res_json = runner.invoke(app, ["verify-diff", clean_diff, "--db", db_path, "--format", "json", "--output", json_out])
    assert res_json.exit_code == 0
    with open(json_out, "r", encoding="utf-8") as fh:
        cert_data = json.load(fh)
    assert cert_data["verdict"]["status"] == "PASS"
    assert cert_data["verdict"]["exit_code"] == 0
    assert cert_data["provenance"]["reproducible"] is True

    # 6. SARIF export validation
    sarif_out = str(tmp_path / "results.sarif")
    res_sarif = runner.invoke(app, ["verify-diff", clean_diff, "--db", db_path, "--format", "sarif", "--output", sarif_out])
    assert res_sarif.exit_code == 0
    with open(sarif_out, "r", encoding="utf-8") as fh:
        sarif_data = json.load(fh)
    assert sarif_data["version"] == "2.1.0"
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "VerifyCI"

    # 7. Invariant violation (eval) -> FAIL (exit 1)
    bad_diff = (
        "diff --git a/billing.py b/billing.py\n"
        "--- a/billing.py\n"
        "+++ b/billing.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def compute_tax(subtotal: float) -> float:\n"
        "-    return subtotal * 0.10\n"
        "+    return eval('subtotal * 0.10')\n"
    )
    res_fail = runner.invoke(app, ["verify-diff", bad_diff, "--db", db_path])
    assert res_fail.exit_code == 1, f"Expected FAIL (1), got {res_fail.exit_code}: {res_fail.output}"
    assert "FAIL" in res_fail.output

    # 8. Secret leak check
    secret_str = "sk_test_1234567890abcdef1234567890abcdef"
    secret_diff = (
        "diff --git a/key.py b/key.py\n"
        "--- /dev/null\n"
        "+++ b/key.py\n"
        "@@ -0,0 +1,1 @@\n"
        f'+token = "{secret_str}"\n'
    )
    sec_json_out = str(tmp_path / "sec_cert.json")
    res_sec = runner.invoke(app, ["verify-diff", secret_diff, "--db", db_path, "--format", "json", "--output", sec_json_out])
    assert res_sec.exit_code == 1
    with open(sec_json_out, "r", encoding="utf-8") as fh:
        sec_cert = json.load(fh)
    assert_no_secret_leak(sec_cert, secret_str)
