"""Regression and adversarial tests for VerifyCI M4 Security analysis engine."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from verifyci.checks.base import CheckContext
from verifyci.checks.security import run as run_security
from verifyci.contracts.model import CheckResult, Coverage, Outcome
from verifyci.gate.orchestrator import _augment_scope_with_repository
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope


def _build_and_run(
    case_id: str,
    base_files: dict[str, str],
    head_files: dict[str, str],
    policy_toml: str,
    tmp_path: Path,
) -> CheckResult:
    repo_dir = tmp_path / case_id
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    repo_dir.mkdir(parents=True)

    subprocess.run(["git", "init", "-q", "-b", "main", str(repo_dir)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.name", "TestRunner"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "config", "user.email", "test@verifyci.dev"], check=True, capture_output=True)

    for rel_path, content in base_files.items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-q", "-m", "base"], check=True, capture_output=True)
    base_commit = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

    for item in repo_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    for rel_path, content in head_files.items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo_dir), "commit", "-q", "-m", "head", "--allow-empty"], check=True, capture_output=True)
    head_commit = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True).strip()

    repo = GitRepo(repo_dir)
    entries, _ = repo.diff_entries(base_commit, head_commit)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(
        scope, git=repo, base_rev=base_commit, head_rev=head_commit, source_roots=()
    )

    policy = parse_policy_bytes(policy_toml.encode("utf-8"))
    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base_commit,
        merge_base_commit=base_commit,
        head_commit=head_commit,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    return run_security(ctx)


@pytest.mark.invariant
def test_precedence_fail_beats_inconclusive(tmp_path: Path):
    """When a validated secret is found alongside an unresolved taint path, FAIL takes precedence."""
    base = {"src/app.py": "def handle(): pass\n"}
    head = {
        "src/app.py": (
            "AWS_KEY = \"AKIA1234567890ABCDEF\"\n"
            "def handle():\n"
            "    user = request.args.get('id')\n"
            "    return user\n"
        )
    }
    policy = (
        "[taint]\n"
        "sources = [\"request.args\"]\n"
        "[taint.sinks.db]\n"
        "symbols = [\"cursor:execute\"]\n"
        "kind = \"sql\"\n"
    )
    res = _build_and_run("prec_fail", base, head, policy, tmp_path)
    assert res.outcome == Outcome.FAIL
    assert res.coverage == Coverage.PARTIAL
    assert any(f.defect_id == "SEC-SECRET" for f in res.findings)
    assert "taint_path_unresolved" in res.reason_codes


@pytest.mark.invariant
def test_allowlist_selectivity(tmp_path: Path):
    """Allowlisted paths pass secrets safely, but non-allowlisted files in the same diff fail."""
    base = {
        "fixtures/sample.py": "# empty\n",
        "src/prod.py": "def init(): pass\n",
    }
    head = {
        "fixtures/sample.py": "TEST_KEY = \"AKIA1234567890ABCDEF\"\n",
        "src/prod.py": "PROD_KEY = \"AKIA0987654321FEDCBA\"\ndef init(): pass\n",
    }
    policy = "[secrets]\nallowlist_paths = [\"fixtures/**\"]\n"
    res = _build_and_run("allowlist_selective", base, head, policy, tmp_path)
    assert res.outcome == Outcome.FAIL
    assert len(res.findings) == 1
    assert res.findings[0].subject["path"] == "src/prod.py"


@pytest.mark.invariant
def test_custom_placeholders_respected(tmp_path: Path):
    """Custom placeholder patterns from target-base policy are ignored as secrets."""
    base = {"src/conf.py": "def cfg(): pass\n"}
    head = {
        "src/conf.py": (
            "api_key = \"mock_sandbox_key_for_testing\"\n"
            "def cfg(): return api_key\n"
        )
    }
    policy = "[secrets]\nplaceholder_patterns = [\"mock_sandbox_key_for_testing\"]\n"
    res = _build_and_run("custom_placeholder", base, head, policy, tmp_path)
    assert res.outcome == Outcome.PASS
    assert res.coverage == Coverage.COMPLETE
    assert not res.findings


@pytest.mark.invariant
def test_strict_redaction_across_multiple_secrets(tmp_path: Path):
    """Every detected secret must be 100% redacted in findings, evidence, and messages."""
    raw_secrets = [
        "AKIA1234567890ABCDEF",
        "ghp_123456789012345678901234",
        "rk_live_0123456789ABCDEF0123",
    ]
    base = {"src/keys.py": "def get(): pass\n"}
    head = {
        "src/keys.py": "\n".join(f"K{i} = \"{s}\"" for i, s in enumerate(raw_secrets)) + "\n"
    }
    res = _build_and_run("redaction_multi", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    assert len(res.findings) == 3
    for f in res.findings:
        payload = f.evidence.payload
        redacted = payload.get("redacted", "")
        assert "…" in redacted
        for s in raw_secrets:
            assert s not in f.message
            assert s not in json.dumps(payload)


@pytest.mark.invariant
def test_unsupported_language_taint_unknown_coverage(tmp_path: Path):
    """Diff touching an unsupported language file under configured taint policy yields UNKNOWN coverage."""
    base = {"lib/core.rs": "fn run() {}\n"}
    head = {"lib/core.rs": "fn run() { let x = 1; }\n"}
    policy = (
        "[taint]\n"
        "sources = [\"request.args\"]\n"
        "[taint.sinks.db]\n"
        "symbols = [\"cursor:execute\"]\n"
        "kind = \"sql\"\n"
    )
    res = _build_and_run("unsupported_taint", base, head, policy, tmp_path)
    assert res.outcome == Outcome.INCONCLUSIVE
    assert res.coverage == Coverage.UNKNOWN
    assert "unsupported_language" in res.reason_codes
    assert not res.findings


@pytest.mark.invariant
def test_multiline_dangerous_call(tmp_path: Path):
    """Multiline dangerous call split across lines is detected syntax-aware."""
    base = {"src/runner.py": "def run(): pass\n"}
    head = {
        "src/runner.py": (
            "def run(cmd):\n"
            "    eval(\n"
            "        cmd\n"
            "    )\n"
        )
    }
    res = _build_and_run("multiline_call", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    assert any(f.defect_id == "SEC-DANGEROUS-CALL" and f.subject.get("symbol") == "eval" for f in res.findings)


@pytest.mark.invariant
def test_aliased_dangerous_call(tmp_path: Path):
    """Import-aliased dangerous call is resolved to its underlying forbidden symbol."""
    base = {"src/exec.py": "def execute(): pass\n"}
    head = {
        "src/exec.py": (
            "from os import system as sys_exec\n"
            "def execute(cmd):\n"
            "    return sys_exec(cmd)\n"
        )
    }
    res = _build_and_run("alias_call", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    assert any(f.defect_id == "SEC-DANGEROUS-CALL" for f in res.findings)


@pytest.mark.invariant
def test_dynamic_dangerous_call_fails_closed_inconclusive(tmp_path: Path):
    """Dynamic callee expression (e.g. getattr dispatch) cannot be verified safe and returns INCONCLUSIVE with dynamic_call gap."""
    base = {"src/dispatch.py": "def run(): pass\n"}
    head = {
        "src/dispatch.py": (
            "import os\n"
            "def run(cmd):\n"
            "    getattr(os, 'system')(cmd)\n"
        )
    }
    res = _build_and_run("dynamic_call_gap", base, head, "", tmp_path)
    assert res.outcome == Outcome.INCONCLUSIVE
    assert res.coverage == Coverage.PARTIAL
    assert "dynamic_call" in res.reason_codes
    assert not res.findings


@pytest.mark.invariant
def test_taint_sink_only_fails_closed_inconclusive(tmp_path: Path):
    """Sink alone on changed line without resolved source produces INCONCLUSIVE with taint_path_unresolved."""
    base = {"src/db.py": "def run(): pass\n"}
    head = {
        "src/db.py": (
            "def run(cursor, query):\n"
            "    cursor.execute(query)\n"
        )
    }
    policy = (
        "[taint]\n"
        "sources = [\"request.args\"]\n"
        "[taint.sinks.db]\n"
        "symbols = [\"cursor:execute\"]\n"
        "kind = \"sql\"\n"
    )
    res = _build_and_run("sink_only_gap", base, head, policy, tmp_path)
    assert res.outcome == Outcome.INCONCLUSIVE
    assert res.coverage == Coverage.PARTIAL
    assert "taint_path_unresolved" in res.reason_codes
    assert not res.findings


@pytest.mark.invariant
def test_aliased_builtin_eval_fails_closed(tmp_path: Path):
    """Aliased eval imported from builtins (e.g. from builtins import eval as e) must fail with SEC-DANGEROUS-CALL."""
    base = {"src/eval_runner.py": "def run(x): pass\n"}
    head = {
        "src/eval_runner.py": (
            "from builtins import eval as e\n"
            "def run(user_input):\n"
            "    return e(user_input)\n"
        )
    }
    res = _build_and_run("alias_eval", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    findings = [f for f in res.findings if f.defect_id == "SEC-DANGEROUS-CALL"]
    assert len(findings) == 1
    assert findings[0].subject.get("symbol") == "eval"
    assert findings[0].evidence.kind.value == "call_site"
    assert findings[0].evidence.payload.get("callee") == "eval"


@pytest.mark.invariant
def test_aliased_builtin_exec_and_compile_fail_closed(tmp_path: Path):
    """Aliased exec, compile, and qualified builtins.eval must all fail closed with SEC-DANGEROUS-CALL."""
    base = {"src/calls.py": "def f(): pass\n"}
    head = {
        "src/calls.py": (
            "import builtins as b\n"
            "from builtins import exec as x, compile as c\n"
            "def run(cmd):\n"
            "    b.eval(cmd)\n"
            "    x(cmd)\n"
            "    c(cmd, '<string>', 'exec')\n"
        )
    }
    res = _build_and_run("alias_exec_compile", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    dangerous = [f for f in res.findings if f.defect_id == "SEC-DANGEROUS-CALL"]
    callees = {f.evidence.payload.get("callee") for f in dangerous}
    assert "eval" in callees
    assert "exec" in callees
    assert "compile" in callees


@pytest.mark.invariant
def test_secret_to_sink_same_line_detected_and_redacted(tmp_path: Path):
    """Secret directly passed into a log or print sink is detected as SEC-SECRET-TO-SINK with strict redaction."""
    raw_secret = "ghp_123456789012345678901234"
    base = {"src/sink_test.py": "def notify(): pass\n"}
    head = {
        "src/sink_test.py": (
            f"import logging\n"
            f"logger = logging.getLogger(__name__)\n"
            f"def notify():\n"
            f"    logger.info('Active token: %s', '{raw_secret}')\n"
        )
    }
    res = _build_and_run("secret_to_sink_direct", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    sink_findings = [f for f in res.findings if f.defect_id == "SEC-SECRET-TO-SINK"]
    assert len(sink_findings) >= 1
    finding = sink_findings[0]
    assert finding.evidence.kind.value == "taint_path"
    assert raw_secret not in finding.message
    assert raw_secret not in json.dumps(finding.evidence.payload)
    assert "…" in finding.evidence.payload["source"]["redacted"]


@pytest.mark.invariant
def test_secret_to_sink_multiline_dataflow(tmp_path: Path):
    """Secret assigned to variable and passed to persistence/print sink is detected as SEC-SECRET-TO-SINK."""
    raw_secret = "AKIA1234567890ABCDEF"
    base = {"src/flow.py": "def log_key(): pass\n"}
    head = {
        "src/flow.py": (
            f"AWS_KEY = '{raw_secret}'\n"
            f"def log_key():\n"
            f"    print('Key is: ' + AWS_KEY)\n"
        )
    }
    res = _build_and_run("secret_to_sink_flow", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    secret_findings = [f for f in res.findings if f.defect_id == "SEC-SECRET"]
    sink_findings = [f for f in res.findings if f.defect_id == "SEC-SECRET-TO-SINK"]
    assert len(secret_findings) == 1
    assert len(sink_findings) == 1
    assert sink_findings[0].evidence.kind.value == "taint_path"
    assert raw_secret not in sink_findings[0].message
    assert raw_secret not in json.dumps(sink_findings[0].evidence.payload)
    assert sink_findings[0].subject.get("symbol") == "AWS_KEY"




@pytest.mark.invariant
def test_secret_flow_to_unchanged_existing_sink(tmp_path: Path):
    """When a secret assignment is added to an existing variable consumed by an unchanged sink, SEC-SECRET-TO-SINK is emitted."""
    raw_secret = "AKIA1234567890ABCDEF"
    base = {
        "src/service.py": (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "API_KEY = 'PLACEHOLDER_NOT_SECRET'\n"
            "def report():\n"
            "    logger.info('Reporting with key: %s', API_KEY)\n"
        )
    }
    head = {
        "src/service.py": (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            f"API_KEY = '{raw_secret}'\n"
            "def report():\n"
            "    logger.info('Reporting with key: %s', API_KEY)\n"
        )
    }
    res = _build_and_run("secret_to_unchanged_sink", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    sink_findings = [f for f in res.findings if f.defect_id == "SEC-SECRET-TO-SINK"]
    assert len(sink_findings) >= 1
    assert sink_findings[0].subject.get("symbol") == "API_KEY"
    assert raw_secret not in json.dumps(sink_findings[0].evidence.payload)


@pytest.mark.invariant
def test_secret_to_aliased_sink_detected(tmp_path: Path):
    """Secret flowing into an imported alias of a logging/print sink is detected."""
    raw_secret = "ghp_123456789012345678901234"
    base = {"src/alias_sink.py": "def run(): pass\n"}
    head = {
        "src/alias_sink.py": (
            "from logging import error as log_err\n"
            f"token = '{raw_secret}'\n"
            "def run():\n"
            "    log_err('Failed token: %s', token)\n"
        )
    }
    res = _build_and_run("secret_to_aliased_sink", base, head, "", tmp_path)
    assert res.outcome == Outcome.FAIL
    sink_findings = [f for f in res.findings if f.defect_id == "SEC-SECRET-TO-SINK"]
    assert len(sink_findings) >= 1
    assert sink_findings[0].subject.get("symbol") == "token"
    assert raw_secret not in json.dumps(sink_findings[0].evidence.payload)
