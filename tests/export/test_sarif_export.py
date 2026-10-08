"""Tests for OASIS SARIF v2.1.0 exporter."""
import json
from typer.testing import CliRunner

from verifyci.export.sarif import export_sarif, SARIF_SCHEMA_URI, SARIF_VERSION
from verifyci.interface.cli import app
from verifyci.interface.commands.ingest import run_ingest
from verifyci.interface.commands.verify import run_verify
from verifyci.secrets.redaction import assert_no_secret_leak


def _setup_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    run_ingest(str(repo))
    return repo


DIFF_PASS = (
    "diff --git a/calc.py b/calc.py\n"
    "--- a/calc.py\n"
    "+++ b/calc.py\n"
    "@@ -1,2 +1,3 @@\n"
    " def add(a, b):\n"
    "     return a + b\n"
    "+    # documented fast path\n"
)
# NOTE (P0): the previous fixture was an equal-line value swap
# (`-return a+b` / `+return (a+b)`), which fail-closed Class-2 now routes
# to INCONCLUSIVE without an execution witness. Exporter PASS-shape tests
# use a pure addition instead, which carries no deletion claim.

DIFF_GUARD_FAIL = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,3 +1,3 @@\n"
    " def check():\n"
    "-    require_auth()\n"
    "+    return 1\n"
    "     return 1\n"
)

DIFF_UNGROUNDED = (
    "diff --git a/unknown.py b/unknown.py\n"
    "--- a/unknown.py\n"
    "+++ b/unknown.py\n"
    "@@ -1,1 +1,2 @@\n"
    " x = 1\n"
    "+y = 2\n"
)

RAW_SECRET = "sk_test_1234567890abcdef1234567890"
DIFF_SECRET = (
    "diff --git a/creds.py b/creds.py\n"
    "--- /dev/null\n"
    "+++ b/creds.py\n"
    "@@ -0,0 +1,1 @@\n"
    f'+api_key = "{RAW_SECRET}"\n'
)


def _validate_sarif_basic_schema(data: dict):
    assert data["$schema"] == SARIF_SCHEMA_URI
    assert data["version"] == SARIF_VERSION
    assert "runs" in data and len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "VerifyCI"
    assert "rules" in run["tool"]["driver"]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run.get("results", []):
        assert res["ruleId"] in rule_ids, f"ruleId {res['ruleId']} missing from driver rules"
        assert res["level"] in ("error", "warning", "note", "none")
        assert res["kind"] in ("fail", "review", "open", "pass", "informational", "notApplicable")
        assert "message" in res and "text" in res["message"]


def test_export_sarif_pass(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_PASS, db_path=db, return_artifacts=True)
    assert res["status"] == "PASS"

    sarif_str = export_sarif(res)
    data = json.loads(sarif_str)
    _validate_sarif_basic_schema(data)

    run = data["runs"][0]
    # Passing run has 0 error/warning alerts
    assert len(run.get("results", [])) == 0
    # Invocation reports success
    invocations = run["invocations"]
    assert len(invocations) == 1
    assert invocations[0]["executionSuccessful"] is True
    assert invocations[0]["properties"]["verdict"] == "PASS"


def test_export_sarif_fail_guard_removal(tmp_path):
    repo = _setup_repo(tmp_path)
    (repo / "app.py").write_text("def check():\n    require_auth()\n    return 1\n", encoding="utf-8")
    run_ingest(str(repo))
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_GUARD_FAIL, db_path=db, return_artifacts=True)
    assert res["status"] == "FAIL"

    sarif_str = export_sarif(res)
    data = json.loads(sarif_str)
    _validate_sarif_basic_schema(data)

    run = data["runs"][0]
    results = run["results"]
    assert len(results) > 0
    # Guard removal is an actual verification failure -> level error, kind fail
    error_results = [r for r in results if r["level"] == "error"]
    assert len(error_results) > 0
    for r in error_results:
        assert r["kind"] == "fail"


def test_export_sarif_fail_secret(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_SECRET, db_path=db, return_artifacts=True)
    assert res["status"] == "FAIL"

    sarif_str = export_sarif(res)
    data = json.loads(sarif_str)
    _validate_sarif_basic_schema(data)

    # Must not leak secret in SARIF
    assert_no_secret_leak(sarif_str, RAW_SECRET)

    run = data["runs"][0]
    sec_results = [r for r in run["results"] if r["ruleId"] == "secrets_scan"]
    assert len(sec_results) == 1
    assert sec_results[0]["level"] == "error"
    assert sec_results[0]["kind"] == "fail"


def test_export_sarif_inconclusive_preserves_uncertainty(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_UNGROUNDED, db_path=db, return_artifacts=True)
    assert res["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW")

    sarif_str = export_sarif(res)
    data = json.loads(sarif_str)
    _validate_sarif_basic_schema(data)

    run = data["runs"][0]
    results = run["results"]
    # Inconclusive/unestablished must NOT be marked as an error!
    for r in results:
        if not r.get("properties", {}).get("established", True):
            assert r["level"] == "note", "Unestablished checks must be mapped to note level"
            assert r["kind"] == "open"


def test_export_sarif_infra_error(tmp_path):
    ghost_db = str(tmp_path / "ghost.db")

    res = run_verify(DIFF_PASS, db_path=ghost_db, return_artifacts=True)
    assert res["status"] == "INFRA_ERROR"

    sarif_str = export_sarif(res)
    data = json.loads(sarif_str)
    _validate_sarif_basic_schema(data)

    run = data["runs"][0]
    # Execution must be marked unsuccessful
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["properties"]["verdict"] == "INFRA_ERROR"

    infra_results = [r for r in run["results"] if r["ruleId"] == "storage_unavailable"]
    assert len(infra_results) == 1
    assert infra_results[0]["level"] == "error"


def test_cli_verify_diff_format_sarif(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")
    runner = CliRunner()

    res = runner.invoke(app, ["verify-diff", DIFF_PASS, "--db", db, "--format", "sarif"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    _validate_sarif_basic_schema(data)


def test_cli_verify_diff_sarif_output_file(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")
    runner = CliRunner()

    out_file = str(tmp_path / "results.sarif")
    res = runner.invoke(app, ["verify-diff", DIFF_PASS, "--db", db, "--format", "sarif", "--output", out_file])
    assert res.exit_code == 0

    with open(out_file, "r", encoding="utf-8") as fh:
        saved = json.load(fh)
    _validate_sarif_basic_schema(saved)
