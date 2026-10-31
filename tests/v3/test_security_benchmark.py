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


# ==============================================================================
# Provenance Authentication & Standalone Signer Adversarial Tests
# ==============================================================================

def test_standalone_signer_entrypoint_isolation_and_path_clearing():
    """Adversarial test: standalone_signer.py entrypoint isolates sys.path and never imports repo code."""
    import subprocess
    import sys
    from scripts.validate_release import ROOT

    # 1. Test execution of the real signer entrypoint as __main__
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "standalone_signer.py"), "--help"],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )
    assert proc.returncode == 0, f"Signer entrypoint execution failed:\n{proc.stderr}\n{proc.stdout}"

    # 2. Test that isolated execution environment purges repo paths and verifyci is absent
    code = (
        "import scripts.standalone_signer as s\n"
        "import sys, pathlib\n"
        "s.assert_no_repository_imports()\n"
        "root = pathlib.Path.cwd().resolve()\n"
        "assert 'verifyci' not in sys.modules, 'verifyci imported'\n"
        "for p in sys.path:\n"
        "    if not p or p == '.':\n"
        "        continue\n"
        "    pr = pathlib.Path(p).resolve()\n"
        "    if (pr == root or pr.is_relative_to(root)) and 'site-packages' not in pr.parts and 'dist-packages' not in pr.parts:\n"
        "        raise AssertionError(f'unpurged repo path: {p}')\n"
    )
    proc2 = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT))
    assert proc2.returncode == 0, f"Isolation test failed:\n{proc2.stderr}\n{proc2.stdout}"


def test_standalone_signer_rejects_shadow_packages_and_protects_key(tmp_path):
    """Adversarial test: standalone_signer.py prevents shadow packages from executing or exfiltrating the signing key."""
    import os
    import shutil
    import subprocess
    import sys
    from scripts.validate_release import ROOT

    # Create simulated candidate repository
    sim_repo = tmp_path / "candidate_repo"
    sim_repo.mkdir()
    sim_scripts = sim_repo / "scripts"
    sim_scripts.mkdir()

    # Copy standalone_signer.py to simulated repo scripts
    real_signer = ROOT / "scripts" / "standalone_signer.py"
    target_signer = sim_scripts / "standalone_signer.py"
    shutil.copyfile(real_signer, target_signer)

    # Place a malicious shadow package 'scripts/cryptography'
    shadow_pkg = sim_scripts / "cryptography"
    shadow_pkg.mkdir()
    exfil_file = tmp_path / "key_exfiltrated.txt"
    (shadow_pkg / "__init__.py").write_text(
        f"""
import os
from pathlib import Path
key = os.environ.get("VERIFYCI_RELEASE_SIGNING_KEY")
Path({repr(str(exfil_file))}).write_text(f"STOLEN_KEY: {{key}}")
raise RuntimeError("Malicious shadow package executed!")
""",
        encoding="utf-8",
    )

    # Execute signer with canary key in environment
    canary_key = "secret_canary_key_0123456789abcdef"
    env = dict(os.environ)
    env["VERIFYCI_RELEASE_SIGNING_KEY"] = canary_key

    proc = subprocess.run(
        [sys.executable, str(target_signer), "--help"],
        cwd=str(sim_repo),
        capture_output=True,
        text=True,
        env=env,
    )

    # Security proof: The shadow package code was NEVER executed and key was NEVER exfiltrated
    assert not exfil_file.exists(), "CRITICAL SECURITY LEAK: Malicious shadow package executed and exfiltrated key!"
    assert "Malicious shadow package executed!" not in proc.stderr
    assert "Malicious shadow package executed!" not in proc.stdout


def _make_valid_measurement_record(root: Path) -> dict:
    import platform
    import time
    from scripts.standalone_signer import (
        MEASUREMENTS_SCHEMA,
        PINNED_CORPORA_HASHES,
        PINNED_MANIFEST_HASH,
        PINNED_TOOLCHAIN_FINGERPRINT,
        compute_implementation_fingerprint,
    )

    return {
        "schema": MEASUREMENTS_SCHEMA,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "manifest_hash": PINNED_MANIFEST_HASH,
        "toolchain_fingerprint": PINNED_TOOLCHAIN_FINGERPRINT,
        "toolchain_identity": {
            "os": platform.system().lower(),
            "python_version": platform.python_version(),
        },
        "corpora_hashes": PINNED_CORPORA_HASHES,
        "implementation_fingerprint": compute_implementation_fingerprint(root),
        "measurements": {
            "benchmark": {
                "cases_evaluated": 22,
                "defects": {
                    "SEC-DANGEROUS-CALL": {"precision": 1.0, "recall": 1.0},
                    "SEC-SECRET": {"precision": 1.0, "recall": 1.0},
                    "SEC-SECRET-TO-SINK": {"precision": 1.0, "recall": 1.0},
                    "SEC-TAINT-TO-SINK": {"precision": 1.0, "recall": 1.0},
                },
                "duration_seconds": 1.0,
                "strict_redaction": True,
                "zero_false_blocking": True,
            },
            "test_suite": {
                "duration_seconds": 1.0,
                "stage": "final",
                "total_errors": 0,
                "total_failed": 0,
                "total_passed": 235,
            },
        },
    }


def test_provenance_rejects_artifact_replacement(tmp_path, monkeypatch):
    """Adversarial test: modifying measurements.json causes cryptographic digest mismatch."""
    import json
    from scripts.standalone_signer import sign_release_evidence
    from scripts.validate_release import ROOT, generate_measurement_attestation

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    m_rec = _make_valid_measurement_record(ROOT)

    m_file = tmp_path / "measurements.json"
    att_file = tmp_path / "measurement_attestation.json"
    out_file = tmp_path / "release_validation.json"

    m_file.write_text(json.dumps(m_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    att_rec, att_errs = generate_measurement_attestation(ROOT, m_rec, att_file, measurements_file=m_file)
    assert not att_errs

    # Tamper with measurements.json after attestation was generated
    tampered_rec = dict(m_rec)
    tampered_rec["measurements"]["test_suite"]["total_passed"] += 1
    m_file.write_text(json.dumps(tampered_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    fake_signing_key = "12" * 32
    rec, errors = sign_release_evidence(ROOT, m_file, att_file, out_file, fake_signing_key)
    assert rec is None
    assert any("mismatch" in e for e in errors), f"Expected mismatch error, got {errors}"


def _generate_test_rsa_jwks():
    from cryptography.hazmat.primitives.asymmetric import rsa
    import base64

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    pn = pub.public_numbers()

    def uint_to_b64url(val):
        b = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
        return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-kid-1",
                "n": uint_to_b64url(pn.n),
                "e": uint_to_b64url(pn.e),
            }
        ]
    }
    return priv, jwks


def _create_signed_jwt(priv_key, header: dict, payload: dict) -> str:
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    import base64
    import json

    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    h_b64 = b64url_encode(json.dumps(header).encode("utf-8"))
    p_b64 = b64url_encode(json.dumps(payload).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = priv_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    sig_b64 = b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{sig_b64}"


def test_oidc_verification_valid_signature_and_claims_passes():
    """Adversarial test: authentic RSA-signed OIDC token passes cryptographic verification."""
    import time
    from scripts.standalone_signer import verify_github_oidc_token

    priv, jwks = _generate_test_rsa_jwks()
    header = {"alg": "RS256", "kid": "test-kid-1", "typ": "JWT"}
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "verifyci-release-authority",
        "exp": time.time() + 300,
        "nbf": time.time() - 10,
        "repository": "NeutronZero/VerifyCI",
        "sha": "a" * 40,
        "run_id": "10001",
        "run_attempt": "1",
        "job_workflow_ref": "NeutronZero/VerifyCI/.github/workflows/ci.yml@refs/heads/feat/v3.1.10-m4-security",
    }
    token = _create_signed_jwt(priv, header, payload)
    claims, errors = verify_github_oidc_token(
        token, "NeutronZero/VerifyCI", "a" * 40, "10001", "1", jwks=jwks
    )
    assert not errors, f"Unexpected errors: {errors}"
    assert claims is not None
    assert claims["run_id"] == "10001"


def test_oidc_verification_rejects_tampered_signature():
    """Adversarial test: forged or modified OIDC signature is cryptographically rejected."""
    import time
    from scripts.standalone_signer import verify_github_oidc_token

    priv, jwks = _generate_test_rsa_jwks()
    header = {"alg": "RS256", "kid": "test-kid-1", "typ": "JWT"}
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "verifyci-release-authority",
        "exp": time.time() + 300,
        "nbf": time.time() - 10,
        "repository": "NeutronZero/VerifyCI",
        "sha": "a" * 40,
        "run_id": "10001",
        "run_attempt": "1",
        "job_workflow_ref": "NeutronZero/VerifyCI/.github/workflows/ci.yml@refs/heads/feat/v3.1.10-m4-security",
    }
    token = _create_signed_jwt(priv, header, payload)
    parts = token.split(".")
    tampered_sig = ("B" if parts[2][0] != "B" else "C") + parts[2][1:]
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    claims, errors = verify_github_oidc_token(
        tampered_token, "NeutronZero/VerifyCI", "a" * 40, "10001", "1", jwks=jwks
    )
    assert claims is None
    assert any("signature verification failed" in e for e in errors)


def test_oidc_verification_rejects_tampered_payload():
    """Adversarial test: modified claims without matching signature fail closed."""
    import base64
    import json
    import time
    from scripts.standalone_signer import verify_github_oidc_token

    priv, jwks = _generate_test_rsa_jwks()
    header = {"alg": "RS256", "kid": "test-kid-1", "typ": "JWT"}
    payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "verifyci-release-authority",
        "exp": time.time() + 300,
        "nbf": time.time() - 10,
        "repository": "NeutronZero/VerifyCI",
        "sha": "a" * 40,
        "run_id": "10001",
        "run_attempt": "1",
        "job_workflow_ref": "NeutronZero/VerifyCI/.github/workflows/ci.yml@refs/heads/feat/v3.1.10-m4-security",
    }
    token = _create_signed_jwt(priv, header, payload)
    parts = token.split(".")
    payload["run_id"] = "99999"  # Tamper with run_id
    tampered_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
    tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

    claims, errors = verify_github_oidc_token(
        tampered_token, "NeutronZero/VerifyCI", "a" * 40, "10001", "1", jwks=jwks
    )
    assert claims is None
    assert any("signature verification failed" in e for e in errors)


def test_oidc_verification_rejects_expired_and_untrusted_claims():
    """Adversarial test: expired tokens, untrusted issuers, wrong audience, or wrong repo fail closed."""
    import time
    from scripts.standalone_signer import verify_github_oidc_token

    priv, jwks = _generate_test_rsa_jwks()
    header = {"alg": "RS256", "kid": "test-kid-1", "typ": "JWT"}
    base_payload = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "verifyci-release-authority",
        "exp": time.time() + 300,
        "nbf": time.time() - 10,
        "repository": "NeutronZero/VerifyCI",
        "sha": "a" * 40,
        "run_id": "10001",
        "run_attempt": "1",
        "job_workflow_ref": "NeutronZero/VerifyCI/.github/workflows/ci.yml@refs/heads/feat/v3.1.10-m4-security",
    }

    # 1. Expired token
    p_exp = dict(base_payload, exp=time.time() - 100)
    t_exp = _create_signed_jwt(priv, header, p_exp)
    c1, e1 = verify_github_oidc_token(t_exp, "NeutronZero/VerifyCI", "a" * 40, "10001", "1", jwks=jwks)
    assert c1 is None and any("expired" in e for e in e1)

    # 2. Untrusted issuer
    p_iss = dict(base_payload, iss="https://evil.token.actions.com")
    t_iss = _create_signed_jwt(priv, header, p_iss)
    c2, e2 = verify_github_oidc_token(t_iss, "NeutronZero/VerifyCI", "a" * 40, "10001", "1", jwks=jwks)
    assert c2 is None and any("untrusted OIDC issuer" in e for e in e2)

    # 3. Untrusted audience
    p_aud = dict(base_payload, aud="evil-audience")
    t_aud = _create_signed_jwt(priv, header, p_aud)
    c3, e3 = verify_github_oidc_token(t_aud, "NeutronZero/VerifyCI", "a" * 40, "10001", "1", jwks=jwks)
    assert c3 is None and any("untrusted OIDC audience" in e for e in e3)

    # 4. Repository mismatch
    p_repo = dict(base_payload, repository="Attacker/VerifyCI")
    t_repo = _create_signed_jwt(priv, header, p_repo)
    c4, e4 = verify_github_oidc_token(t_repo, "NeutronZero/VerifyCI", "a" * 40, "10001", "1", jwks=jwks)
    assert c4 is None and any("repository mismatch" in e for e in e4)


def test_standalone_signer_rejects_missing_oidc_token_in_ci(tmp_path, monkeypatch):
    """Adversarial test: in CI environment, attestation without OIDC token fails closed."""
    import json
    from scripts.standalone_signer import sign_release_evidence, get_commit_sha
    from scripts.validate_release import ROOT

    commit_sha = get_commit_sha(ROOT)
    assert commit_sha

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "10001")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_SHA", commit_sha)
    monkeypatch.setenv("GITHUB_REPOSITORY", "NeutronZero/VerifyCI")
    monkeypatch.setenv("GITHUB_TOKEN", "mock_ci_token")

    m_rec = _make_valid_measurement_record(ROOT)
    m_file = tmp_path / "measurements.json"
    att_file = tmp_path / "measurement_attestation.json"
    out_file = tmp_path / "release_validation.json"

    m_raw = (json.dumps(m_rec, indent=2, sort_keys=True) + "\n").encode("utf-8")
    import hashlib
    from verifyci.evidence.canonical import canonical_json_bytes
    raw_sha = "sha256:" + hashlib.sha256(m_raw).hexdigest()
    can_sha = "sha256:" + hashlib.sha256(canonical_json_bytes(m_rec)).hexdigest()

    att_rec = {
        "schema": "verifyci.measurement_attestation/v1",
        "issuer": "verifyci.measurement_pipeline",
        "created_at": "2026-10-31T12:00:00Z",
        "execution": {
            "ci_platform": "github_actions",
            "workflow_run_id": "10001",
            "workflow_run_attempt": "1",
            "commit_sha": commit_sha,
        },
        "workflow_identity": {
            "platform": "github_actions",
            "repository": "NeutronZero/VerifyCI",
            "run_id": "10001",
            "run_attempt": "1",
            "commit_sha": commit_sha,
        },
        "measurements_digest": can_sha,
        "measurements_file_sha256": raw_sha,
        "implementation_fingerprint": m_rec["implementation_fingerprint"],
        "manifest_hash": m_rec["manifest_hash"],
        "corpora_hashes": m_rec["corpora_hashes"],
    }
    m_file.write_bytes(m_raw)
    att_file.write_text(json.dumps(att_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    fake_signing_key = "12" * 32
    rec, errors = sign_release_evidence(ROOT, m_file, att_file, out_file, fake_signing_key)
    assert rec is None
    assert any("missing required OIDC token in CI environment" in e for e in errors)


def test_verify_release_validation_enforces_ci_provenance(tmp_path, monkeypatch):
    """Adversarial test: verify_release_validation_evidence rejects unauthenticated CI provenance when require_ci=True."""
    from scripts.validate_release import ROOT
    from verifyci.contracts import release_validation

    # 1. Evidence with local provenance must fail when require_ci=True
    raw_evidence = json.loads((ROOT / "evidence" / "release" / "release_validation.json").read_text(encoding="utf-8"))
    recorded_commit = raw_evidence["commit_sha"]
    recorded_fp = raw_evidence["implementation_fingerprint"]
    local_record = dict(raw_evidence)
    local_record["provenance"] = {
        "ci_platform": "local",
        "ci_verified": False,
        "commit_sha": recorded_commit,
    }
    real_read = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: json.dumps(local_record).encode("utf-8") if self.name == "release_validation.json" else real_read(self),
    )
    monkeypatch.setattr(release_validation.hmac, "compare_digest", lambda a, b: True)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    monkeypatch.setattr(Ed25519PublicKey, "verify", lambda *args, **kwargs: None)
    monkeypatch.setattr(release_validation, "compute_implementation_fingerprint", lambda root: recorded_fp)
    monkeypatch.setattr(release_validation, "get_commit_sha", lambda root=None: recorded_commit)

    ok, err = release_validation.verify_release_validation_evidence(require_ci=True)
    assert not ok
    assert "ci_verified must be true" in err

    # 2. Incomplete CI provenance must fail
    mock_record = dict(raw_evidence)
    mock_record["provenance"] = {
        "ci_platform": "github_actions",
        "ci_verified": True,
        # missing workflow_run_id, job_id, artifact_id, etc.
    }
    real_read = Path.read_bytes
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: json.dumps(mock_record).encode("utf-8") if self.name == "release_validation.json" else real_read(self),
    )
    monkeypatch.setattr(release_validation.hmac, "compare_digest", lambda a, b: True)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    monkeypatch.setattr(Ed25519PublicKey, "verify", lambda *args, **kwargs: None)

    ok2, err2 = release_validation.verify_release_validation_evidence(require_ci=True)
    assert not ok2
    assert "missing required CI field" in err2

    # 3. Provenance with oidc_verified == False must fail
    mock_record3 = dict(raw_evidence)
    mock_record3["provenance"] = {
        "ci_platform": "github_actions",
        "ci_verified": True,
        "workflow_run_id": "123",
        "job_id": "456",
        "artifact_id": "789",
        "measurement_job_completed_at": "2026-10-31T12:00:00Z",
        "artifact_created_at": "2026-10-31T12:00:00Z",
        "oidc_verified": False,
        "commit_sha": recorded_commit,
    }
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: json.dumps(mock_record3).encode("utf-8") if self.name == "release_validation.json" else real_read(self),
    )
    ok3, err3 = release_validation.verify_release_validation_evidence(require_ci=True)
    assert not ok3
    assert "oidc_verified must be true" in err3


def test_provenance_rejects_fabricated_failed_measurements(tmp_path, monkeypatch):
    """Adversarial test: measurement artifact with failed tests fails closed."""
    import json
    from scripts.standalone_signer import sign_release_evidence
    from scripts.validate_release import ROOT, generate_measurement_attestation

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    m_rec = _make_valid_measurement_record(ROOT)

    # Fabricate failing measurement
    m_rec["measurements"]["test_suite"]["total_failed"] = 1
    m_file = tmp_path / "measurements.json"
    att_file = tmp_path / "measurement_attestation.json"
    out_file = tmp_path / "release_validation.json"

    m_file.write_text(json.dumps(m_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    att_rec, att_errs = generate_measurement_attestation(ROOT, m_rec, att_file, measurements_file=m_file)
    assert not att_errs

    fake_signing_key = "12" * 32
    rec, errors = sign_release_evidence(ROOT, m_file, att_file, out_file, fake_signing_key)
    assert rec is None
    assert any("failing or errored" in e for e in errors), f"Expected failure rejection, got {errors}"


def test_provenance_rejects_mismatched_run_id_in_ci(tmp_path, monkeypatch):
    """Adversarial test: in CI environment, mismatched run ID fails closed."""
    import json
    from scripts.standalone_signer import sign_release_evidence, get_commit_sha
    from scripts.validate_release import ROOT, generate_measurement_attestation

    commit_sha = get_commit_sha(ROOT)
    assert commit_sha

    m_rec = _make_valid_measurement_record(ROOT)

    m_file = tmp_path / "measurements.json"
    att_file = tmp_path / "measurement_attestation.json"
    out_file = tmp_path / "release_validation.json"

    # Generate attestation first
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    m_file.write_text(json.dumps(m_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    att_rec, att_errs = generate_measurement_attestation(ROOT, m_rec, att_file, measurements_file=m_file)
    assert not att_errs

    # Set CI execution identity in attestation
    att_rec["execution"]["ci_platform"] = "github_actions"
    att_rec["execution"]["workflow_run_id"] = "10001"
    att_rec["execution"]["workflow_run_attempt"] = "1"
    att_rec["execution"]["commit_sha"] = commit_sha
    att_file.write_text(json.dumps(att_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Set CI environment variables for signing with a mismatched run ID
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "10002")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_SHA", commit_sha)
    monkeypatch.setenv("GITHUB_REPOSITORY", "NeutronZero/VerifyCI")
    monkeypatch.setenv("GITHUB_TOKEN", "mock_token")

    fake_signing_key = "12" * 32
    rec, errors = sign_release_evidence(ROOT, m_file, att_file, out_file, fake_signing_key)
    assert rec is None
    assert any("workflow run ID mismatch" in e for e in errors), f"Expected run ID mismatch, got {errors}"


def test_provenance_rejects_unsuccessful_job_in_ci(tmp_path, monkeypatch):
    """Adversarial test: in CI environment, uncompleted/unsuccessful measurement job fails closed."""
    import json
    from scripts.standalone_signer import sign_release_evidence, get_commit_sha
    from scripts.validate_release import ROOT, generate_measurement_attestation

    commit_sha = get_commit_sha(ROOT)
    assert commit_sha

    m_rec = _make_valid_measurement_record(ROOT)

    m_file = tmp_path / "measurements.json"
    att_file = tmp_path / "measurement_attestation.json"
    out_file = tmp_path / "release_validation.json"

    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    m_file.write_text(json.dumps(m_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    att_rec, att_errs = generate_measurement_attestation(ROOT, m_rec, att_file, measurements_file=m_file)
    assert not att_errs

    att_rec["execution"]["ci_platform"] = "github_actions"
    att_rec["execution"]["workflow_run_id"] = "20001"
    att_rec["execution"]["workflow_run_attempt"] = "1"
    att_rec["execution"]["commit_sha"] = commit_sha
    att_file.write_text(json.dumps(att_rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "20001")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GITHUB_SHA", commit_sha)
    monkeypatch.setenv("GITHUB_REPOSITORY", "NeutronZero/VerifyCI")
    monkeypatch.setenv("GITHUB_TOKEN", "mock_token")

    # Custom verifier simulating GitHub API reporting job conclusion == 'failure'
    def mock_verifier(att):
        return None, ["measurement job 'verifyci-measurements' conclusion is 'failure' (expected 'success')"]

    fake_signing_key = "12" * 32
    rec, errors = sign_release_evidence(
        ROOT, m_file, att_file, out_file, fake_signing_key, custom_verifier=mock_verifier
    )
    assert rec is None
    assert any("conclusion is 'failure'" in e for e in errors), f"Expected conclusion failure, got {errors}"


def test_provenance_rejects_artifact_window_out_of_bounds():
    """Adversarial test: artifact creation timestamp outside job execution window fails closed."""
    from scripts.standalone_signer import verify_github_actions_provenance
    import unittest.mock as mock

    # Mock urllib response for run, jobs, and artifacts
    run_response = {"path": ".github/workflows/ci.yml"}
    jobs_response = {
        "jobs": [
            {
                "id": 100,
                "name": "verifyci-measurements",
                "status": "completed",
                "conclusion": "success",
                "head_sha": "a" * 40,
                "started_at": "2026-10-31T12:00:00Z",
                "completed_at": "2026-10-31T12:05:00Z",
                "steps": [
                    {"name": "Run Evidence & Benchmark Reproduction Gate", "conclusion": "success"},
                    {"name": "Run Unprivileged Benchmark & Test Measurements Pipeline", "conclusion": "success"},
                    {"name": "Upload Release Measurements Artifact", "conclusion": "success"},
                ],
            }
        ]
    }
    # Artifact created at 12:20:00Z (15 minutes after job completed)
    artifacts_response = {
        "artifacts": [
            {
                "id": 200,
                "name": "release-measurements",
                "size_in_bytes": 5000,
                "created_at": "2026-10-31T12:20:00Z",
            }
        ]
    }

    class MockResp:
        def __init__(self, data):
            self.data = json.dumps(data).encode("utf-8")

        def read(self):
            return self.data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def mock_urlopen(req, timeout=30):
        url = req.full_url
        if "/jobs" in url:
            return MockResp(jobs_response)
        elif "/artifacts" in url:
            return MockResp(artifacts_response)
        elif "/runs/" in url:
            return MockResp(run_response)
        raise ValueError(f"Unknown URL {url}")

    with mock.patch("urllib.request.urlopen", side_effect=mock_urlopen):
        prov, errors = verify_github_actions_provenance(
            "NeutronZero/VerifyCI", "1", "1", "a" * 40, "mock_token"
        )
    assert prov is None
    assert any("outside job execution window" in e for e in errors)


def test_provenance_rejects_missing_measurement_step():
    """Adversarial test: job missing required measurement step fails closed."""
    from scripts.standalone_signer import verify_github_actions_provenance
    import unittest.mock as mock

    run_response = {"path": ".github/workflows/ci.yml"}
    jobs_response = {
        "jobs": [
            {
                "id": 100,
                "name": "verifyci-measurements",
                "status": "completed",
                "conclusion": "success",
                "head_sha": "a" * 40,
                "started_at": "2026-10-31T12:00:00Z",
                "completed_at": "2026-10-31T12:05:00Z",
                "steps": [
                    # Missing "Upload Release Measurements Artifact" step
                    {"name": "Run Evidence & Benchmark Reproduction Gate", "conclusion": "success"},
                    {"name": "Run Unprivileged Benchmark & Test Measurements Pipeline", "conclusion": "success"},
                ],
            }
        ]
    }

    class MockResp:
        def __init__(self, data):
            self.data = json.dumps(data).encode("utf-8")

        def read(self):
            return self.data

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def mock_urlopen(req, timeout=30):
        url = req.full_url
        if "/jobs" in url:
            return MockResp(jobs_response)
        elif "/runs/" in url:
            return MockResp(run_response)
        raise ValueError(f"Unknown URL {url}")

    with mock.patch("urllib.request.urlopen", side_effect=mock_urlopen):
        prov, errors = verify_github_actions_provenance(
            "NeutronZero/VerifyCI", "1", "1", "a" * 40, "mock_token"
        )
    assert prov is None
    assert any("required measurement step" in e for e in errors)


