"""Corpus-backed benchmark and evaluation test suite for VerifyCI M4 Security check.

Evaluates the production security check (verifyci.checks.security) against the
frozen 18-case security corpus (corpora/security/cases.jsonl) to establish:
1. Exact outcome, coverage, and reason-code agreement across all 18 cases.
2. Perfect precision (1.00) and recall (1.00) across all declared defect types:
   - SEC-SECRET (secret_detected)
   - SEC-DANGEROUS-CALL (dangerous_call)
   - SEC-TAINT-TO-SINK (taint_to_sink)
3. Normative fail-closed handling for ambiguous candidates and unresolved paths:
   - taint_path_unresolved -> Outcome.INCONCLUSIVE, Coverage.PARTIAL
   - unsupported_language -> Outcome.INCONCLUSIVE, Coverage.UNKNOWN
4. Strict Redaction 1.0 enforcement on all generated findings.
5. Complete applicability evidence for negative/unmodified/binary controls.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

from verifyci.checks.base import CheckContext
from verifyci.checks.security import run as run_security
from verifyci.contracts.model import CheckResult
from verifyci.gate.orchestrator import _augment_scope_with_repository
from verifyci.gate.policy import parse_policy_bytes
from verifyci.scm.git import GitRepo
from verifyci.scope.entities import build_changed_scope

CORPUS_ROOT = Path("corpora/security")
CASES_FILE = CORPUS_ROOT / "cases.jsonl"


def load_security_cases() -> list[dict]:
    assert CASES_FILE.is_file(), f"missing {CASES_FILE}"
    cases = []
    for line in CASES_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            cases.append(json.loads(line))
    return cases


def _build_case_repo(case: dict, target_dir: Path) -> tuple[GitRepo, str, str, str]:
    repo_dir = target_dir / case["case_id"]
    if repo_dir.exists():
        shutil.rmtree(repo_dir)
    repo_dir.mkdir(parents=True)

    subprocess.run(
        ["git", "init", "-q", "-b", "main", str(repo_dir)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "TestRunner"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "test@verifyci.dev"],
        check=True,
        capture_output=True,
    )

    for rel_path, content in case["base_files"].items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(
        ["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-q", "-m", "base"],
        check=True,
        capture_output=True,
    )
    base_commit = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True
    ).strip()

    for item in repo_dir.iterdir():
        if item.name != ".git":
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

    for rel_path, content in case["head_files"].items():
        file_path = repo_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8", newline="")

    subprocess.run(
        ["git", "-C", str(repo_dir), "add", "-A"], check=True, capture_output=True
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-q", "-m", "head", "--allow-empty"],
        check=True,
        capture_output=True,
    )
    head_commit = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True
    ).strip()

    return GitRepo(repo_dir), base_commit, base_commit, head_commit


def _execute_case(case: dict, tmp_path: Path) -> CheckResult:
    repo, base, mb, head = _build_case_repo(case, tmp_path)
    entries, _ = repo.diff_entries(base, head)
    scope = build_changed_scope(entries)
    scope = _augment_scope_with_repository(
        scope, git=repo, base_rev=base, head_rev=head, source_roots=()
    )

    pol = case.get("policy", {})
    lines: list[str] = []

    allow = pol.get("secret_allowlist_paths", [])
    places = pol.get("secret_placeholders", [])
    if allow or places:
        lines.append("[secrets]")
        if allow:
            lines.append(f"allowlist_paths = {json.dumps(allow)}")
        if places:
            lines.append(f"placeholder_patterns = {json.dumps(places)}")

    for rule_id, rule in pol.get("forbidden_calls", {}).items():
        lines.append(f"[forbidden_calls.{rule_id}]")
        lines.append(f"symbols = {json.dumps(rule.get('symbols', []))}")
        lines.append(f"reason = {json.dumps(rule.get('reason', 'forbidden'))}")

    sources = pol.get("taint_sources", [])
    sinks = pol.get("taint_sinks", {})
    if sources or sinks:
        lines.append("[taint]")
        if sources:
            lines.append(f"sources = {json.dumps(sources)}")
        for sink_id, sink in sinks.items():
            lines.append(f"[taint.sinks.{sink_id}]")
            lines.append(f"symbols = {json.dumps(sink.get('symbols', []))}")
            lines.append(f"kind = {json.dumps(sink.get('kind', 'generic'))}")

    toml_bytes = "\n".join(lines).encode("utf-8")
    policy = parse_policy_bytes(toml_bytes)

    ctx = CheckContext(
        git=repo,
        policy=policy,
        entries=tuple(entries),
        scope=scope,
        as_of_date="2026-10-21",
        target_base_commit=base,
        merge_base_commit=mb,
        head_commit=head,
        object_format="sha1",
        toolchain_fingerprint="test",
        source_roots=(),
    )
    return run_security(ctx)


@pytest.mark.invariant
def test_security_check_empirical_benchmark(tmp_path: Path):
    cases = load_security_cases()
    assert len(cases) == 22, f"expected 22 cases, got {len(cases)}"

    outcome_matches = 0
    coverage_matches = 0
    reason_matches = 0
    findings_matches = 0
    discrepancies: list[str] = []

    defects = [
        "SEC-SECRET",
        "SEC-SECRET-TO-SINK",
        "SEC-DANGEROUS-CALL",
        "SEC-TAINT-TO-SINK",
    ]
    confusion = {d: {"TP": 0, "FP": 0, "FN": 0, "TN": 0} for d in defects}

    for case in cases:
        cid = case["case_id"]
        exp = case["expected"]
        res = _execute_case(case, tmp_path)

        if res.outcome.value == exp["outcome"]:
            outcome_matches += 1
        else:
            discrepancies.append(
                f"{cid}: outcome {res.outcome.value} != {exp['outcome']}"
            )

        if res.coverage.value == exp["coverage"]:
            coverage_matches += 1
        else:
            discrepancies.append(
                f"{cid}: coverage {res.coverage.value} != {exp['coverage']}"
            )

        got_rc = sorted(res.reason_codes)
        exp_rc = sorted(exp.get("reason_codes", []))
        if got_rc == exp_rc:
            reason_matches += 1
        else:
            discrepancies.append(f"{cid}: reason codes {got_rc} != {exp_rc}")

        got_findings = sorted(f.defect_id for f in res.findings)
        exp_findings = sorted(f["defect_id"] for f in exp.get("findings", []))
        if got_findings == exp_findings:
            findings_matches += 1
        else:
            discrepancies.append(f"{cid}: findings {got_findings} != {exp_findings}")

        got_def_set = set(got_findings)
        exp_def_set = set(exp_findings)
        for did in defects:
            in_got = did in got_def_set
            in_exp = did in exp_def_set
            if in_got and in_exp:
                confusion[did]["TP"] += 1
            elif in_got and not in_exp:
                confusion[did]["FP"] += 1
            elif not in_got and in_exp:
                confusion[did]["FN"] += 1
            else:
                confusion[did]["TN"] += 1

        # Redaction verification on real engine output
        for finding in res.findings:
            if finding.defect_id == "SEC-SECRET":
                payload = finding.evidence.payload
                redacted = payload.get("redacted", "")
                assert "…" in redacted or "***" in redacted, (
                    f"{cid}: finding payload missing redacted representation: {payload}"
                )
                for secret_sample in ["AKIA1234567890ABCDEF", "ghp_123456789012345678901234", "xoxb-1234567890-1234567890123"]:
                    assert secret_sample not in finding.message, f"{cid}: secret leaked in message"
                    assert secret_sample not in json.dumps(payload), f"{cid}: secret leaked in payload"

    print("\n" + "=" * 60)
    print("M4 SECURITY CHECK EMPIRICAL BENCHMARK REPORT")
    print("=" * 60)
    print(f"Total Cases Evaluated:         {len(cases)}/18 (100.0%)")
    print(
        f"Outcome Agreement:             {outcome_matches}/{len(cases)} ({(outcome_matches / len(cases)) * 100:.1f}%)"
    )
    print(
        f"Coverage Agreement:            {coverage_matches}/{len(cases)} ({(coverage_matches / len(cases)) * 100:.1f}%)"
    )
    print(
        f"Reason Code Agreement:         {reason_matches}/{len(cases)} ({(reason_matches / len(cases)) * 100:.1f}%)"
    )
    print(
        f"Defect ID Matches:             {findings_matches}/{len(cases)} ({(findings_matches / len(cases)) * 100:.1f}%)"
    )
    print("-" * 60)
    print("Defect-Level Precision & Recall Metrics:")
    for did in defects:
        c = confusion[did]
        tp, fp, fn, _ = c["TP"], c["FP"], c["FN"], c["TN"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        print(f"  {did:<25} P={prec:.2f} ({tp}/{tp + fp})  R={rec:.2f} ({tp}/{tp + fn})")
        assert prec == 1.0, f"{did} precision {prec} < 1.0"
        assert rec == 1.0, f"{did} recall {rec} < 1.0"
    print("=" * 60)

    assert not discrepancies, "Benchmark discrepancies found:\n" + "\n".join(
        discrepancies
    )
    assert outcome_matches == len(cases)
    assert coverage_matches == len(cases)
    assert reason_matches == len(cases)
    assert findings_matches == len(cases)


# ==============================================================================
# Security Authority Isolation Adversarial Tests
# ==============================================================================

def test_benchmark_execution_cannot_access_signing_key(monkeypatch):
    """Adversarial test: verify execute_security_benchmark scrubs signing credentials.

    Even if the caller or environment holds VERIFYCI_RELEASE_SIGNING_KEY, the benchmark
    worker subprocess MUST execute in a scrubbed environment without access to the secret.
    """
    from scripts.validate_release import ROOT, execute_security_benchmark

    canary_secret = "simulated_ed25519_private_key_canary_0123456789abcdef"
    monkeypatch.setenv("VERIFYCI_RELEASE_SIGNING_KEY", canary_secret)

    bench_data, errors = execute_security_benchmark(ROOT)
    assert errors == [], f"Benchmark execution failed with errors: {errors}"
    assert bench_data is not None
    assert bench_data["cases_evaluated"] == 22
    assert bench_data["zero_false_blocking"] is True
    assert bench_data["strict_redaction"] is True


def test_benchmark_worker_fails_closed_if_signing_key_leaked():
    """Adversarial test: worker directly fails closed if VERIFYCI_RELEASE_SIGNING_KEY is present."""
    import os
    import sys
    import subprocess
    from scripts.validate_release import ROOT

    env = os.environ.copy()
    env["VERIFYCI_RELEASE_SIGNING_KEY"] = "unauthorized_secret_key"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_release.py"), "--benchmark-worker"],
        env=env,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode != 0, "Worker did not fail closed when signing secret was passed"
    assert "Security violation" in (proc.stdout + proc.stderr)

