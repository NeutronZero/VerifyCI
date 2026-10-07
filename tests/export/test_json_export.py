"""Tests for stable machine-readable Certificate and Report JSON exporter."""
import json
from typer.testing import CliRunner

from verifyci.export.json import export_certificate_json
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
    "@@ -1,2 +1,2 @@\n"
    " def add(a, b):\n"
    "-    return a + b\n"
    "+    return (a + b)\n"
)

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

RAW_SECRET = "AIzaSyD-ExampleSecretKey998877665544"
DIFF_SECRET = (
    "diff --git a/creds.py b/creds.py\n"
    "--- /dev/null\n"
    "+++ b/creds.py\n"
    "@@ -0,0 +1,1 @@\n"
    f'+api_key = "{RAW_SECRET}"\n'
)


def test_export_json_pass_structure(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_PASS, db_path=db, return_artifacts=True)
    assert res["status"] == "PASS"

    rendered = export_certificate_json(res)
    data = json.loads(rendered)

    assert data["$schema"] == "https://verifyci.org/schemas/v1/certificate-report.json"
    assert data["version"] == "1.0"
    assert data["verdict"]["status"] == "PASS"
    assert data["verdict"]["exit_code"] == 0
    assert "all_checks_passed_behavior_not_verified" in data["verdict"]["rationale"]
    assert data["provenance"]["reproducible"] is True
    assert "calc.py" in data["provenance"]["files"]
    assert data["certificate"] is not None
    assert data["certificate"]["certificate_verified"] is True
    assert data["report"] is not None
    assert len(data["report"]["checks"]) > 0


def test_export_json_fail_structure(tmp_path):
    repo = _setup_repo(tmp_path)
    (repo / "app.py").write_text("def check():\n    require_auth()\n    return 1\n", encoding="utf-8")
    run_ingest(str(repo))
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_GUARD_FAIL, db_path=db, return_artifacts=True)
    assert res["status"] == "FAIL"

    rendered = export_certificate_json(res)
    data = json.loads(rendered)

    assert data["verdict"]["status"] == "FAIL"
    assert data["verdict"]["exit_code"] == 1
    assert data["verdict"]["rationale"] == "blocking_check_failed"
    assert data["certificate"] is not None


def test_export_json_inconclusive_structure(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_UNGROUNDED, db_path=db, return_artifacts=True)
    assert res["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW")

    rendered = export_certificate_json(res)
    data = json.loads(rendered)

    assert data["verdict"]["status"] in ("INCONCLUSIVE", "HUMAN_REVIEW")
    assert data["verdict"]["exit_code"] == 2


def test_export_json_infra_error_structure(tmp_path):
    ghost_db = str(tmp_path / "ghost.db")

    res = run_verify(DIFF_PASS, db_path=ghost_db, return_artifacts=True)
    assert res["status"] == "INFRA_ERROR"

    rendered = export_certificate_json(res)
    data = json.loads(rendered)

    assert data["verdict"]["status"] == "INFRA_ERROR"
    assert data["verdict"]["exit_code"] == 3
    assert data["infra_error"] == "db_not_found"


def test_export_json_does_not_leak_raw_secret(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")

    res = run_verify(DIFF_SECRET, db_path=db, return_artifacts=True)
    assert res["status"] == "FAIL"

    rendered = export_certificate_json(res)
    # Rigorous boundary assertion: raw secret string and fragments must not appear in exported JSON
    assert_no_secret_leak(rendered, RAW_SECRET)


def test_cli_verify_diff_format_json(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")
    runner = CliRunner()

    res = runner.invoke(app, ["verify-diff", DIFF_PASS, "--db", db, "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["verdict"]["status"] == "PASS"


def test_cli_verify_diff_json_output_file(tmp_path):
    repo = _setup_repo(tmp_path)
    db = str(repo / ".verifyci" / "verifyci.db")
    runner = CliRunner()

    out_file = str(tmp_path / "cert.json")
    res = runner.invoke(app, ["verify-diff", DIFF_PASS, "--db", db, "--format", "json", "--output", out_file])
    assert res.exit_code == 0

    with open(out_file, "r", encoding="utf-8") as fh:
        saved = json.load(fh)
    assert saved["verdict"]["status"] == "PASS"
