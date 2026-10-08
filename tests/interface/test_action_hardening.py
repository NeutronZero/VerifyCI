"""PHASE 1-A: GitHub Action / CI execution-boundary hardening tests.

Two layers:
1. Static gates on action.yml: zero `${{ }}` interpolation in the `run:`
   body (all caller input arrives via `env:`), random heredoc delimiters,
   `--` git separator, constrained install, input allowlists.
2. Adversarial execution harness: the extracted `run:` body is executed
   under bash with stubbed `verifyci`/`git` and attacker-controlled env
   values (quotes, `$()`, backticks, newlines, heredoc terminators, spaces,
   globs, traversal). A canary file proves no injected syntax executes.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
ACTION_YML = REPO_ROOT / "action.yml"
CONSTRAINTS = REPO_ROOT / "constraints-ci.txt"

BASH = shutil.which("bash")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash not available")


def _wsl_path(p):
    """Translate a Windows path to its WSL /mnt/... form (identity otherwise)."""
    s = str(p).replace("\\", "/")
    if len(s) > 1 and s[1] == ":":
        return "/mnt/" + s[0].lower() + s[2:]
    return s


def _bash_is_wsl():
    """True when BASH is the Windows WSL launcher (needs path translation)."""
    if os.name != "nt" or not BASH:
        return False
    assert BASH is not None
    try:
        proc = subprocess.run(
            [BASH, "-c", "printf %s \"$WSL_DISTRO_NAME$WSL_INTEROP\""],
            capture_output=True, text=True, timeout=60,
        )
        return bool(proc.stdout.strip())
    except Exception:
        return False


def _action():
    return yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))


def _run_body():
    data = _action()
    steps = data["runs"]["steps"]
    assert len(steps) >= 1
    return steps[0]["run"]


def _run_env():
    data = _action()
    return steps_env(data)


def steps_env(data):
    steps = data["runs"]["steps"]
    assert len(steps) >= 1
    return steps[0].get("env", {})


# --------------------------------------------------------------------------
# 1. Static gates
# --------------------------------------------------------------------------

def test_action_run_body_has_zero_template_interpolation():
    body = _run_body()
    assert "${{" not in body, (
        "run: body must not contain ${{ }} interpolation; "
        "pass every input through the env: block instead"
    )


def test_action_env_covers_all_inputs_plus_action_path():
    env = _run_env()
    for var in (
        "INPUT_PATH", "INPUT_DB", "INPUT_BASE_REF", "INPUT_HEAD_REF",
        "INPUT_FORMAT", "INPUT_OUTPUT_FILE", "INPUT_FAIL_ON_INC",
        "ACTION_PATH",
    ):
        assert var in env, f"env: block missing {var}"
    assert "inputs.path" in env["INPUT_PATH"]
    assert "inputs.output-file" in env["INPUT_OUTPUT_FILE"]
    assert "github.action_path" in env["ACTION_PATH"]


def test_action_outputs_still_wired():
    data = _action()
    assert data["outputs"]["status"]["value"] == "${{ steps.run-verifyci.outputs.status }}"
    assert data["outputs"]["exit-code"]["value"] == "${{ steps.run-verifyci.outputs.exit_code }}"


def test_action_uses_random_heredoc_delimiter():
    body = _run_body()
    # A fixed delimiter lets a crafted rationale line truncate/inject outputs.
    assert re.search(r"<<\s*[\"']?EOF_VERIFYCI[\"']?\s*$", body, re.M) is None, (
        "fixed EOF_VERIFYCI heredoc delimiter still present"
    )
    assert "RANDOM" in body, "expected per-run random delimiter material"


def test_action_git_diff_uses_double_dash_separator():
    body = _run_body()
    assert 'git diff "$BASE_REF" "$HEAD_REF" --' in body


def test_action_install_is_constrained():
    body = _run_body()
    assert "constraints-ci.txt" in body
    assert CONSTRAINTS.is_file()


def test_action_validates_format_and_output_file():
    body = _run_body()
    assert "sarif|json|text" in body
    assert '".."' in body or "'..'" in body or "/../" in body


def test_action_sanitizes_status_output():
    body = _run_body()
    assert "tr -cd" in body


def test_action_enforces_strict_shell_options():
    body = _run_body()
    assert "set -uo pipefail" in body or "set -o pipefail" in body


@needs_bash
def test_action_run_body_passes_bash_syntax_check(tmp_path):
    assert BASH is not None  # guaranteed by the needs_bash marker
    script = tmp_path / "step.sh"
    script.write_text(
        _run_body().replace("\r\n", "\n"), encoding="utf-8", newline="\n")
    script_arg = _wsl_path(script) if _bash_is_wsl() else str(script)
    proc = subprocess.run(
        [BASH, "-n", script_arg], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


def _normalized(name):
    return name.lower().replace("-", "_").replace(".", "_")


def test_constraints_match_uv_lock():
    """constraints-ci.txt must pin exactly the runtime deps at uv.lock versions."""
    lock = tomllib.load(open(REPO_ROOT / "uv.lock", "rb"))
    locked = {}
    for pkg in lock["package"]:
        locked[_normalized(pkg["name"])] = pkg["version"]
    pins = {}
    for line in CONSTRAINTS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, version = line.partition("==")
        assert version, f"unpinned constraint line: {line!r}"
        pins[_normalized(name)] = version
    # Every pyproject runtime dependency must be pinned ...
    project = tomllib.load(open(REPO_ROOT / "pyproject.toml", "rb"))
    for dep in project["project"]["dependencies"]:
        dep_name = re.split(r"[<>=!~\s\[]", dep.strip(), maxsplit=1)[0]
        key = _normalized(dep_name)
        assert key in pins, f"runtime dep {dep_name!r} missing from constraints-ci.txt"
        assert pins[key] == locked[key], (
            f"{dep_name}: constraints {pins[key]} != uv.lock {locked[key]}"
        )
    # ... and every pin must correspond to a real runtime dependency.
    dep_keys = {
        _normalized(re.split(r"[<>=!~\s\[]", d.strip(), maxsplit=1)[0])
        for d in project["project"]["dependencies"]
    }
    assert set(pins) == dep_keys


# --------------------------------------------------------------------------
# 2. Adversarial execution harness
# --------------------------------------------------------------------------

CANARY = "CANARY_PWNED"


def _write_stub(bin_dir, name, content):
    p = bin_dir / name
    # LF unconditionally: stubs execute under bash/WSL.
    p.write_text(content, encoding="utf-8", newline="\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _harness(tmp_path, monkeypatch, *, env_extra, stub_exit="0",
             stub_status="PASS", stub_rationale="all good"):
    """Run the action's `run:` body with stubbed tool/git binaries.

    Returns (returncode, files_created, github_output_text, argv_log).
    """
    assert BASH is not None  # guaranteed by the needs_bash marker
    body = _run_body()
    # Normalize line endings: the composite step executes under bash, which
    # requires LF. (GitHub checks out action.yml with LF on Linux runners;
    # a CRLF working copy must never change the executed semantics.)
    script = tmp_path / "step.sh"
    script.write_text(body.replace("\r\n", "\n"), encoding="utf-8", newline="\n")

    wsl = _bash_is_wsl()
    # Forward slashes everywhere inside the shell: WSL needs /mnt paths,
    # native Git-bash will not convert quoted backslash paths on
    # redirection, so Windows separators must never reach the script.
    sh = _wsl_path if wsl else (lambda p: str(p).replace("\\", "/"))

    bin_dir = tmp_path / "stubs"
    bin_dir.mkdir()
    argv_log = tmp_path / "argv.log"
    report_path = tmp_path / "STUB_REPORT_PATH"

    # The action script invokes `python` for JSON parsing. Under WSL the
    # Windows interpreter is unusable with /mnt paths, so provide a `python`
    # stub delegating to the guest interpreter; on native bash the stub
    # delegates to this very interpreter (forward slashes: executable by
    # the Windows loader when invoked from msys).
    if wsl:
        python_bin = "python3"
    else:
        python_bin = sys.executable.replace("\\", "/")
    _write_stub(bin_dir, "python", f"#!/usr/bin/env bash\nexec \"{python_bin}\" \"$@\"\n")
    _write_stub(bin_dir, "verifyci", f"""#!/usr/bin/env bash
echo "verifyci $@" >> "{sh(argv_log)}"
cmd="$1"; shift || true
if [ "$cmd" = "verify-diff" ]; then
  out=""; fmt=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --output) out="$2"; shift 2 ;;
      --format) fmt="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  echo "$out" > "{sh(report_path)}"
  STUB_STATUS="${{STUB_STATUS}}" STUB_RATIONALE="${{STUB_RATIONALE}}" STUB_FMT="$fmt" OUT="$out" "{python_bin}" - <<'PYEOF'
import json, os
status = os.environ.get("STUB_STATUS", "PASS")
rationale = os.environ.get("STUB_RATIONALE", "all good")
out = os.environ.get("OUT", "")
if os.environ.get("STUB_FMT", "") == "json":
    report = {{"verdict": {{"status": status, "rationale": rationale}}}}
else:
    report = {{"runs": [{{"invocations": [{{"properties": {{"verdict": status, "rationale": rationale}}}}]}}]}}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh)
PYEOF
  exit "$STUB_EXIT"
fi
exit 0
""")
    _write_stub(bin_dir, "git", f"""#!/usr/bin/env bash
echo "git $@" >> "{sh(argv_log)}"
if [ "$1" = "diff" ]; then
  printf 'diff --git a/app.py b/app.py\\n+ok\\n'
  exit 0
fi
exit 0
""")

    # Extensionless stubs created by Python lack the executable bit that
    # native Windows shells (Git-bash) require for PATH lookup: without
    # this, bash silently skips the stubs and the REAL verifyci/git/python
    # run instead (observed on CI). chmod through the test shell itself so
    # the bit is set in a way msys honors. WSL/DrvFs files are already
    # executable; the call is harmless there.
    def _shq(value):
        return "'" + value.replace("'", "'\\''") + "'"

    _chmod = subprocess.run(
        [BASH, "-c", "chmod +x " + " ".join(
            _shq(sh(bin_dir / name)) for name in ("verifyci", "git", "python"))],
        capture_output=True, text=True, timeout=60,
    )
    assert _chmod.returncode == 0, _chmod.stderr

    out_file = tmp_path / "GITHUB_OUTPUT"
    out_file.write_text("", encoding="utf-8")
    if wsl:
        path_env = sh(bin_dir) + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    else:
        path_env = sh(bin_dir) + os.pathsep + os.environ.get("PATH", "")
    env = {
        "PATH": path_env,
        "GITHUB_OUTPUT": sh(out_file),
        "GITHUB_WORKSPACE": sh(tmp_path),
        "GITHUB_RUN_ID": "test-run-42",
        "GITHUB_BASE_REF": "",
        "STUB_EXIT": stub_exit,
        "STUB_STATUS": stub_status,
        "STUB_RATIONALE": stub_rationale,
    }
    env.update(env_extra)
    for key in (
        "INPUT_PATH", "INPUT_DB", "INPUT_BASE_REF", "INPUT_HEAD_REF",
        "INPUT_FORMAT", "INPUT_OUTPUT_FILE", "INPUT_FAIL_ON_INC",
        "ACTION_PATH",
    ):
        env.setdefault(key, "")
    # Defaults matching the action's own input defaults (applied only when
    # the caller omits the variable; an explicit empty string is preserved
    # so rejection paths stay testable).
    _defaults = {
        "INPUT_PATH": ".",
        "INPUT_HEAD_REF": "HEAD",
        "INPUT_FORMAT": "sarif",
        "INPUT_OUTPUT_FILE": "verifyci-results.sarif",
        "INPUT_FAIL_ON_INC": "true",
    }
    for key, value in _defaults.items():
        if key not in env_extra:
            env[key] = value
    env.setdefault("ACTION_PATH", sh(REPO_ROOT))
    if wsl:
        # Never leak Windows interpreter/temp configuration into the guest:
        # TMPDIR with backslashes would break mktemp, PYTHON* could hijack
        # the guest interpreter used for report parsing.
        for _key in list(os.environ):
            # Bash identifiers only: names with parens (e.g. Windows
            # COMMONPROGRAMFILES(X86)) are not assignable in the guest.
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", _key):
                continue
            if _key.startswith("PYTHON") or _key in ("TMPDIR", "TEMP", "TMP", "VIRTUAL_ENV"):
                continue
            if _key not in env:
                env[_key] = os.environ[_key]

    def _sq(value):
        return "'" + value.replace("'", "'\\''") + "'"

    if wsl:
        env_file = tmp_path / "test_env.sh"
        env_file.write_text(
            "".join(f"export {key}={_sq(value)}\n" for key, value in env.items()),
            encoding="utf-8",
            newline="\n",
        )
        _probe_cmd = ". " + sh(env_file) + " && command -v verifyci; command -v git; command -v python"
        _probe_env = {"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows")}
    else:
        _probe_cmd = (
            "echo \"PATH-IS:$PATH\"; type -a git; "
            "test -x " + _shq(sh(bin_dir / "git")) + " && echo GIT-STUB-EXEC-YES || echo GIT-STUB-EXEC-NO; "
            "head -c 40 " + _shq(sh(bin_dir / "git")) + " | od -An -c | head -2; "
            "command -v verifyci; command -v git; command -v python"
        )
        _probe_env = dict(env)

    # Preflight: prove the stubs (not the real tools) resolve in PATH.
    # A previous CI failure mode ran the REAL git here with zero signal
    # in the test output about which binary won. Fail loudly instead.
    # NOTE: this must run through the same environment mechanism as the
    # main flow (env-file bridge on WSL, process env natively) — an early
    # version probed with a bare environment and proved nothing.
    _preflight = subprocess.run(
        [BASH, "-c", _probe_cmd + "; ls -la " + _shq(sh(bin_dir))],
        capture_output=True, text=True, timeout=60,
        cwd=tmp_path,
        env=_probe_env,
    )
    _resolved = _preflight.stdout.replace("\\", "/")
    for _tool in ("verifyci", "git", "python"):
        assert f"/stubs/{_tool}" in _resolved, (
            f"stub preflight failed for {_tool} (real tool would run instead):\n{_preflight.stdout}\n{_preflight.stderr}")

    proc = None
    if wsl:
        # WSL only propagates variables listed in WSLENV, so large or
        # hostile values cannot ride the process environment. Bridge them
        # through a file instead: single-quote escaping keeps arbitrary
        # bytes (quotes, $(), backticks, newlines) inert data.
        bridge = ". " + sh(env_file) + " && exec bash " + sh(script)
        proc = subprocess.run(
            [BASH, "-c", bridge],
            cwd=tmp_path,
            env={"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows")},
            capture_output=True, text=True, timeout=120,
        )
    else:
        proc = subprocess.run(
            [BASH, str(script)], cwd=tmp_path, env=env,
            capture_output=True, text=True, timeout=120,
        )
    created = sorted(
        p.name for p in tmp_path.iterdir()
        if p.name not in ("step.sh", "test_env.sh", "GITHUB_OUTPUT", "argv.log", "stubs", "STUB_REPORT_PATH")
        and CANARY not in p.name
    )
    canary_hits = list(tmp_path.rglob(f"*{CANARY}*"))
    argv = argv_log.read_text(encoding="utf-8") if argv_log.exists() else ""
    return proc, created, out_file.read_text(encoding="utf-8"), argv, canary_hits


def _env(**kw):
    return {k: v for k, v in kw.items()}


@needs_bash
@pytest.mark.parametrize("evil_out", [
    "/etc/verifyci.sarif",
    "../../evil.sarif",
    "..\\evil.sarif",
    "",
    "a b.sarif",
    "out$(touch CANARY_PWNED).sarif",
    "out`touch CANARY_PWNED`.sarif",
    "out;touch CANARY_PWNED;.sarif",
    "out|touch CANARY_PWNED.sarif",
    "out\ntouch CANARY_PWNED.sarif",
    "verifyci-results.sarif\nEOF_VERIFYCI",
    "sub/../../evil.sarif",
    "-o.sarif",
    "out*.sarif",
    "out?.sarif",
    "out$.sarif",
])
def test_evil_output_file_rejected_without_execution(tmp_path, monkeypatch, evil_out):
    proc, created, _output, argv, canary = _harness(
        tmp_path, monkeypatch, env_extra=_env(INPUT_OUTPUT_FILE=evil_out))
    assert proc.returncode == 3, f"evil output-file accepted: {evil_out!r}\n{proc.stderr}"
    assert canary == [], f"injected syntax executed for {evil_out!r}"
    assert "verify-diff" not in argv, "tool ran on unvalidated output path"


@needs_bash
@pytest.mark.parametrize("evil_format", [
    "json;touch CANARY_PWNED",
    "sarif\ntouch CANARY_PWNED",
    "xml",
    "JSON",
    "sarif ",
    "$(touch CANARY_PWNED)",
])
def test_evil_format_rejected(tmp_path, monkeypatch, evil_format):
    proc, _c, _o, argv, canary = _harness(
        tmp_path, monkeypatch, env_extra=_env(INPUT_FORMAT=evil_format))
    assert proc.returncode == 3, f"evil format accepted: {evil_format!r}"
    assert canary == []
    assert "verify-diff" not in argv


@needs_bash
@pytest.mark.parametrize("evil_ref", [
    "--output=/tmp/evil",
    "-h",
    "a;touch CANARY_PWNED",
    "a$(touch CANARY_PWNED)",
    "a`touch CANARY_PWNED`",
    "a\ntouch CANARY_PWNED",
    "branch@{1}",
    "a|b",
    "a b",
])
def test_evil_refs_rejected(tmp_path, monkeypatch, evil_ref):
    proc, _c, _o, argv, canary = _harness(
        tmp_path, monkeypatch, env_extra=_env(INPUT_BASE_REF=evil_ref))
    assert proc.returncode == 3, f"evil ref accepted: {evil_ref!r}\n{proc.stderr}"
    assert canary == []
    assert "verify-diff" not in argv


@needs_bash
@pytest.mark.parametrize("evil_path", [
    "-e",
    "--help",
    "a\nb",
    "a;touch CANARY_PWNED",
    "$(touch CANARY_PWNED)",
    "a`touch CANARY_PWNED`",
    "a|touch CANARY_PWNED",
    "a&touch CANARY_PWNED",
    "a>touch",
    "a$HOME",
    'a"quoted',
    "a'quoted",
    "a*b",
    "a?b",
])
def test_evil_paths_rejected(tmp_path, monkeypatch, evil_path):
    proc, _c, _o, _a, canary = _harness(
        tmp_path, monkeypatch, env_extra=_env(INPUT_PATH=evil_path))
    assert proc.returncode == 3, f"evil path accepted: {evil_path!r}"
    assert canary == []


@needs_bash
def test_path_with_spaces_passes_as_single_arg(tmp_path, monkeypatch):
    (tmp_path / "my repo").mkdir()
    proc, _c, _o, argv, canary = _harness(
        tmp_path, monkeypatch, env_extra=_env(INPUT_PATH="my repo"))
    assert canary == []
    init_lines = [ln for ln in argv.splitlines() if ln.startswith("verifyci init ")]
    assert init_lines and init_lines[0] == "verifyci init my repo", argv


@needs_bash
def test_valid_sarif_flow_exit_zero(tmp_path, monkeypatch):
    proc, _c, output, _a, canary = _harness(tmp_path, monkeypatch, env_extra={})
    assert canary == []
    assert proc.returncode == 0, proc.stderr
    assert "\nstatus=PASS\n" in "\n" + output or output.startswith("status=PASS\n")
    assert "exit_code=0" in output
    assert "all good" in output


@needs_bash
def test_evil_rationale_cannot_break_github_output(tmp_path, monkeypatch):
    evil = "line one\nEOF_VERIFYCI\nstatus=FAKE\n rationale=INJECTED\nline three"
    _proc, _c, output, _a, canary = _harness(
        tmp_path, monkeypatch, env_extra={}, stub_rationale=evil)
    assert canary == []
    # Parse the GITHUB_OUTPUT structure: headers, then the heredoc block.
    # Attacker text must survive only as block CONTENT, never as structure.
    lines = output.splitlines()
    hdr_end = next(i for i, ln in enumerate(lines) if ln.startswith("rationale<<"))
    headers = lines[:hdr_end]
    assert headers == ["status=PASS", "exit_code=0"], output
    block = lines[hdr_end + 1:-1]
    assert lines[-1].startswith("verifyci_delim_"), output
    assert "status=FAKE" in block, "rationale must be preserved verbatim"
    assert "line one" in block and "line three" in block


@needs_bash
def test_heredoc_delimiter_is_random_per_run(tmp_path, monkeypatch):
    _p1, _c1, out1, _a1, _c = _harness(tmp_path, monkeypatch, env_extra={})
    tmp2 = tmp_path / "run2"
    tmp2.mkdir()
    _p2, _c2, out2, _a2, _c3 = _harness(tmp2, monkeypatch, env_extra={})
    d1 = [ln for ln in out1.splitlines() if ln.startswith("rationale<<")][0]
    d2 = [ln for ln in out2.splitlines() if ln.startswith("rationale<<")][0]
    assert d1 != d2, "heredoc delimiter is static across runs"


@needs_bash
def test_newline_injected_status_is_sanitized(tmp_path, monkeypatch):
    _proc, _c, output, _a, _c2 = _harness(
        tmp_path, monkeypatch, env_extra={}, stub_status="PASS\ninjected=1")
    lines = output.splitlines()
    status_lines = [ln for ln in lines if ln.startswith("status=")]
    assert len(status_lines) == 1
    assert status_lines[0] == "status=PASSinjected"
    assert "injected=1" not in output.replace("status=PASSinjected", "")
