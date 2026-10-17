"""Security scanning and secret redaction invariant tests."""

from __future__ import annotations

from verifyci.contracts.verdict import FindingReason, VerificationVerdict
from verifyci.core.canonical import redact_token
from verifyci.core.secrets import scan_secrets_in_source
from verifyci.core.security import scan_dangerous_calls


def test_dangerous_builtins_eval_exec() -> None:
    code = "def run_code(user_input: str):\n    eval(user_input)\n"
    findings = scan_dangerous_calls("src/handler.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert findings[0].reason == FindingReason.DANGEROUS_CALL
    assert "eval" in findings[0].message


def test_dangerous_call_with_module_alias() -> None:
    code = (
        "import os as my_os\n"
        "def cleanup():\n"
        "    my_os.system('rm -rf /tmp/data')\n"
    )
    findings = scan_dangerous_calls("src/cleanup.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert findings[0].reason == FindingReason.DANGEROUS_CALL
    assert "os.system" in findings[0].message


def test_dangerous_call_with_from_import_alias() -> None:
    code = (
        "from subprocess import run as exec_cmd\n"
        "def execute(cmd: str):\n"
        "    exec_cmd(cmd, shell=True)\n"
    )
    findings = scan_dangerous_calls("src/runner.py", code, exclude_tests=False)
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert "subprocess.run" in findings[0].message


def test_dangerous_call_test_path_exclusion() -> None:
    code = "import os\ndef test_clean():\n    os.system('rm test.db')\n"
    # Excluded for test paths
    findings = scan_dangerous_calls("tests/test_clean.py", code, exclude_tests=True)
    assert len(findings) == 0


def test_secret_detection_and_redaction_invariant() -> None:
    raw_token = "ghp_1234567890abcdef1234567890abcdef1234"
    code = f'GITHUB_API_KEY = "{raw_token}"\n'
    findings = scan_secrets_in_source("src/client.py", code)

    assert len(findings) > 0
    finding = findings[0]
    assert finding.verdict == VerificationVerdict.FAIL
    assert finding.reason == FindingReason.SECRET_LEAK

    # Strict redaction assertion: raw token must NEVER appear anywhere in finding or details
    assert raw_token not in finding.message
    for key, val in finding.details.items():
        assert raw_token not in str(val)

    # Must contain deterministic mask
    expected_mask = redact_token(raw_token)
    assert expected_mask in finding.message
    assert finding.details.get("redacted_mask") == expected_mask


def test_secret_uri_credential_detection() -> None:
    raw_uri = "postgres://admin:SuperSecretPassword123!@db.internal:5432/prod"
    code = f'DB_URI = "{raw_uri}"\n'
    findings = scan_secrets_in_source("config/settings.py", code)
    assert any(f.reason == FindingReason.SECRET_LEAK for f in findings)
    for f in findings:
        assert "SuperSecretPassword123!" not in f.message
