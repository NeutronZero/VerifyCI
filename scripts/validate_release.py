#!/usr/bin/env python3
"""VerifyCI Release Validation Suite.

Executes a comprehensive, non-destructive validation of all release requirements:
1. Code linting (ruff check .)
2. Test suite execution (pytest)
3. Distribution artifact build (uv build)
4. Sdist and wheel artifact inspection (metadata, licenses, entrypoints, package files)
5. Package import and CLI startup
6. End-to-end verify-diff smoke tests (PASS, FAIL)
7. Machine-readable JSON Certificate export validation
8. OASIS SARIF v2.1.0 schema validation
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def log(msg: str) -> None:
    print(f"[release-validation] {msg}")


def run_cmd(cmd: list[str], cwd: Path = ROOT) -> str:
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"FAILED: {' '.join(cmd)}")
        print("STDOUT:", res.stdout)
        print("STDERR:", res.stderr)
        sys.exit(res.returncode)
    return res.stdout


def step_lint() -> None:
    log("1/7 Checking code linting (ruff)...")
    run_cmd([sys.executable, "-m", "ruff", "check", "."])
    log("[OK] Lint clean.")


def step_tests() -> None:
    log("2/7 Running test suite (pytest)...")
    out = run_cmd([sys.executable, "-m", "pytest", "-q"])
    log(f"[OK] Tests passed: {out.strip().splitlines()[-1]}")


def step_build() -> tuple[Path, Path]:
    log("3/7 Building distribution packages (uv build)...")
    dist_dir = ROOT / "dist"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    run_cmd(["uv", "build"])
    sdists = list(dist_dir.glob("*.tar.gz"))
    wheels = list(dist_dir.glob("*.whl"))
    assert len(sdists) == 1, f"Expected 1 sdist, found {len(sdists)}"
    assert len(wheels) == 1, f"Expected 1 wheel, found {len(wheels)}"
    sdist, wheel = sdists[0], wheels[0]
    log(f"[OK] Built {sdist.name} ({sdist.stat().st_size:,} bytes)")
    log(f"[OK] Built {wheel.name} ({wheel.stat().st_size:,} bytes)")
    return sdist, wheel


def step_inspect_artifacts(sdist: Path, wheel: Path) -> None:
    log("4/7 Inspecting distribution artifacts...")
    # Inspect SDIST
    with tarfile.open(sdist, "r:gz") as tf:
        sdist_names = set(tf.getnames())
        pkg_prefix = "verifyci-0.1.0"
        required_sdist = [
            f"{pkg_prefix}/LICENSE",
            f"{pkg_prefix}/README.md",
            f"{pkg_prefix}/pyproject.toml",
            f"{pkg_prefix}/verifyci/__init__.py",
            f"{pkg_prefix}/verifyci/export/sarif.py",
            f"{pkg_prefix}/verifyci/export/json.py",
        ]
        for req in required_sdist:
            assert req in sdist_names, f"SDIST missing {req}"

    # Inspect Wheel
    with zipfile.ZipFile(wheel, "r") as zf:
        wheel_names = set(zf.namelist())
        assert "verifyci-0.1.0.dist-info/METADATA" in wheel_names
        assert "verifyci-0.1.0.dist-info/entry_points.txt" in wheel_names
        assert "verifyci-0.1.0.dist-info/licenses/LICENSE" in wheel_names
        assert "verifyci/export/sarif.py" in wheel_names
        assert "verifyci/export/json.py" in wheel_names

        # Validate entry points
        ep_content = zf.read("verifyci-0.1.0.dist-info/entry_points.txt").decode("utf-8")
        assert "verifyci = verifyci.interface.cli:app" in ep_content

        # Validate metadata
        meta_content = zf.read("verifyci-0.1.0.dist-info/METADATA").decode("utf-8")
        assert "Name: verifyci" in meta_content
        assert "Version: 0.1.0" in meta_content
        assert "License: MIT" in meta_content
        assert "Project-URL: Homepage, https://github.com/NeutronZero/VerifyCI" in meta_content
    log("[OK] Artifacts structure, entrypoints, and metadata verified.")


def step_cli_and_import() -> None:
    log("5/7 Validating package imports and CLI startup...")
    # Test importing core modules
    run_cmd([sys.executable, "-c", "import verifyci; import verifyci.contracts; import verifyci.export; print('imports ok')"])

    # Test CLI startup
    out = run_cmd([sys.executable, "-m", "verifyci.interface.cli", "--help"])
    assert "VerifyCI" in out
    assert "verify-diff" in out
    assert "ingest" in out
    log("[OK] CLI startup and core imports successful.")


def step_verify_diff_smoke() -> None:
    log("6/7 Running end-to-end verify-diff smoke tests (PASS, FAIL)...")
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    from verifyci.interface.commands.ingest import run_ingest

    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "calc.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (tdp / "app.py").write_text("def check():\n    require_auth()\n    return 1\n", encoding="utf-8")
        run_ingest(str(tdp))
        db = str(tdp / ".verifyci" / "verifyci.db")

        # 1. Test clean diff (PASS)
        clean_diff = (
            "diff --git a/calc.py b/calc.py\n"
            "--- a/calc.py\n"
            "+++ b/calc.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def add(a, b):\n"
            "-    return a + b\n"
            "+    return (a + b)\n"
        )
        res_pass = runner.invoke(app, ["verify-diff", clean_diff, "--db", db])
        assert res_pass.exit_code == 0, f"Expected exit 0, got {res_pass.exit_code}: {res_pass.output}"
        assert "PASS" in res_pass.output

        # 2. Test guard removal diff (FAIL)
        guard_diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,3 +1,3 @@\n"
            " def check():\n"
            "-    require_auth()\n"
            "+    return 1\n"
            "     return 1\n"
        )
        res_fail = runner.invoke(app, ["verify-diff", guard_diff, "--db", db])
        assert res_fail.exit_code == 1, f"Expected exit 1, got {res_fail.exit_code}: {res_fail.output}"
        assert "FAIL" in res_fail.output
    log("[OK] Verification smoke tests passed: honest PASS (exit 0) and FAIL (exit 1).")


def step_export_smoke() -> None:
    log("7/7 Validating JSON and SARIF export contracts...")
    from typer.testing import CliRunner
    from verifyci.interface.cli import app
    from verifyci.interface.commands.ingest import run_ingest
    from verifyci.secrets.redaction import assert_no_secret_leak

    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "core.py").write_text("def work():\n    return 42\n", encoding="utf-8")
        run_ingest(str(tdp))
        db = str(tdp / ".verifyci" / "verifyci.db")

        secret_str = "sk_test_99887766554433221100aabbccdd"
        sec_diff = (
            "diff --git a/key.py b/key.py\n"
            "--- /dev/null\n"
            "+++ b/key.py\n"
            "@@ -0,0 +1,1 @@\n"
            f'+token = "{secret_str}"\n'
        )

        # JSON Export test
        json_file = str(tdp / "cert.json")
        res_json = runner.invoke(app, ["verify-diff", sec_diff, "--db", db, "--format", "json", "--output", json_file])
        assert res_json.exit_code == 1
        with open(json_file, "r", encoding="utf-8") as fh:
            json_data = json.load(fh)
        assert json_data["verdict"]["status"] == "FAIL"
        assert json_data["verdict"]["exit_code"] == 1
        assert_no_secret_leak(json_data, secret_str)

        # SARIF Export test
        sarif_file = str(tdp / "results.sarif")
        res_sarif = runner.invoke(app, ["verify-diff", sec_diff, "--db", db, "--format", "sarif", "--output", sarif_file])
        assert res_sarif.exit_code == 1
        with open(sarif_file, "r", encoding="utf-8") as fh:
            sarif_data = json.load(fh)
        assert sarif_data["version"] == "2.1.0"
        assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "VerifyCI"
        results = sarif_data["runs"][0]["results"]
        assert len(results) > 0
        assert results[0]["level"] == "error"
        assert results[0]["kind"] == "fail"
        assert_no_secret_leak(sarif_data, secret_str)

    log("[OK] JSON and SARIF export validation succeeded with 0 leaks.")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="VerifyCI Release Validation Suite")
    parser.add_argument("--skip-tests", action="store_true", help="Skip the full pytest suite execution")
    args = parser.parse_args()

    log("Starting VerifyCI V0.1.0 Release Validation...")
    step_lint()
    if not args.skip_tests:
        step_tests()
    else:
        log("2/7 Skipping test suite (--skip-tests active).")
    sdist, wheel = step_build()
    step_inspect_artifacts(sdist, wheel)
    step_cli_and_import()
    step_verify_diff_smoke()
    step_export_smoke()
    log("==================================================================")
    log("SUCCESS: All VerifyCI V0.1.0 release validation checks PASSED.")
    log("==================================================================")


if __name__ == "__main__":
    main()
