"""Adversarial and protocol unit test suite for CAP-002B secret detector."""
from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from typing import Any

import pytest

from verifyci.secrets.contracts import (
    DetectorContext,
    ResourceLimitExceeded,
    SecretRule,
)
from verifyci.secrets.engine import SecretDetector
from verifyci.secrets.redaction import assert_no_secret_leak
from verifyci.secrets.rules import RuleRegistry


def _diff(content: str, path: str = "src/app.py", lineno: int = 1) -> str:
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -{lineno},0 +{lineno},1 @@\n"
        f"+{content}\n"
    )


# 1. pwd falsifier (CAP-002 guiding falsifier)
def test_adversarial_pwd_falsifier():
    detector = SecretDetector()
    diff = _diff('pwd = "sk-live-9f8a7b6c5d4e1234567890abcdef"', path="src/db.py")
    findings = detector.scan_diff(diff)
    active = [f for f in findings if f.is_active]
    assert len(active) == 1
    assert active[0].rule_id == "provider_openai_key"
    assert active[0].detector_family == "provider_token"


# 2. x falsifier (single-letter variable name)
def test_adversarial_x_falsifier():
    detector = SecretDetector()
    diff = _diff('x = "ghp_1234567890abcdef1234567890abcdef12"', path="src/auth.py")
    findings = detector.scan_diff(diff)
    active = [f for f in findings if f.is_active]
    assert len(active) == 1
    assert active[0].rule_id == "provider_github_token"


# 3. High-entropy non-secret (UUIDs, git commit hex hashes, math constants)
def test_adversarial_high_entropy_non_secret():
    detector = SecretDetector()
    non_secrets = [
        'commit_sha = "76c19df2b826a6f4ce6fc1749b5314048514298c"',
        'task_uuid = "f5bee46f-014f-444a-a24d-0c60f9846902"',
        'pi_constant = [3.141592653589793, 2.718281828459045]',
        'cache_key = "aBcDeFgHiJkLmNoP"',
    ]
    for ns in non_secrets:
        diff = _diff(ns)
        findings = detector.scan_diff(diff)
        active = [f for f in findings if f.is_active]
        assert active == [], f"Incorrectly flagged non-secret: {ns}"


# 4. Valid structured tokens without keyword context
def test_adversarial_valid_structured_tokens():
    detector = SecretDetector()
    cases = [
        ('target = "AKIAIOSFODNN7EXAMPLE"', "provider_aws_access_key"),
        (
            'raw_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
            "structured_jwt_token",
        ),
        (
            'uri = "postgres://app_user:complexPassword99!@db.internal:5432/main"',
            "credential_connection_string",
        ),
        (
            'key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0...\\n-----END RSA PRIVATE KEY-----\"',
            "crypto_private_key",
        ),
    ]
    for text, expected_rule in cases:
        diff = _diff(text)
        findings = detector.scan_diff(diff)
        active = [f for f in findings if f.is_active]
        assert any(f.rule_id == expected_rule for f in active), f"Failed to detect: {text}"


# 5. Encoded structured token (Base64 and Hex)
def test_adversarial_encoded_structured_token():
    detector = SecretDetector()
    # Base64
    raw_secret = b"sk-live-a1b2c3d4e5f6g7h8i9j0k1l2"
    b64_val = base64.b64encode(raw_secret).decode("utf-8")
    diff_b64 = _diff(f'encoded_key = "{b64_val}"')
    findings_b64 = detector.scan_diff(diff_b64)
    active_b64 = [f for f in findings_b64 if f.is_active]
    assert len(active_b64) >= 1
    assert any(len(f.transforms) > 0 and f.transforms[0].transform_type == "base64" for f in active_b64)

    # Hex
    hex_val = raw_secret.hex()
    diff_hex = _diff(f'hex_key = "{hex_val}"')
    findings_hex = detector.scan_diff(diff_hex)
    active_hex = [f for f in findings_hex if f.is_active]
    assert len(active_hex) >= 1
    assert any(len(f.transforms) > 0 and f.transforms[0].transform_type == "hex" for f in active_hex)


# 6. Same value moved to another line has identical fingerprint
def test_adversarial_same_value_moved_to_another_line():
    detector = SecretDetector()
    val = "sk-live-9f8a7b6c5d4e1234567890abcdef"
    diff1 = _diff(f'token = "{val}"', lineno=10)
    diff2 = _diff(f'token = "{val}"', lineno=450)

    f1 = [f for f in detector.scan_diff(diff1) if f.is_active][0]
    f2 = [f for f in detector.scan_diff(diff2) if f.is_active][0]

    assert f1.finding_fingerprint == f2.finding_fingerprint
    assert f1.line_start == 10
    assert f2.line_start == 450


# 7. Same value under different variable names has identical fingerprint
def test_adversarial_same_value_under_different_variable_names():
    detector = SecretDetector()
    val = "sk-live-9f8a7b6c5d4e1234567890abcdef"
    diff1 = _diff(f'foo = "{val}"')
    diff2 = _diff(f'credential_payload = "{val}"')

    f1 = [f for f in detector.scan_diff(diff1) if f.is_active][0]
    f2 = [f for f in detector.scan_diff(diff2) if f.is_active][0]

    assert f1.finding_fingerprint == f2.finding_fingerprint
    assert f1.rule_id == f2.rule_id


# 8. Path variation and scoped exclusions
def test_adversarial_path_variation():
    detector = SecretDetector()
    # Test fixture mock token in test file
    diff_test = _diff('MOCK_TEST_TOKEN = "mock-token-00000000000000000000"', path="tests/mock.py")
    findings_test = detector.scan_diff(diff_test)
    active_test = [f for f in findings_test if f.is_active]
    assert active_test == []

    # Production code with real secret
    diff_prod = _diff('key = "sk-live-9f8a7b6c5d4e1234567890abcdef"', path="src/prod.py")
    findings_prod = detector.scan_diff(diff_prod)
    active_prod = [f for f in findings_prod if f.is_active]
    assert len(active_prod) == 1


# 9. Multiline variation (parenthesis and backslash)
def test_adversarial_multiline_variation():
    detector = SecretDetector()
    diff_paren = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        "@@ -1,0 +1,3 @@\n"
        "+auth = (\n"
        "+    \"sk-live-88889999aaaabbbbccccdddd\"\n"
        "+)\n"
    )
    findings = detector.scan_diff(diff_paren)
    active = [f for f in findings if f.is_active]
    assert len(active) >= 1
    assert any(f.rule_id == "provider_openai_key" for f in active)


# 10. Overlapping detector findings (specificity hierarchy)
def test_adversarial_overlapping_detector_findings():
    detector = SecretDetector()
    # Matches provider_openai_key (specificity 90) AND keyword_quoted_assignment (specificity 60)
    diff = _diff('api_key = "sk-live-9f8a7b6c5d4e1234567890abcdef"')
    findings = detector.scan_diff(diff)
    active = [f for f in findings if f.is_active]
    suppressed = [f for f in findings if not f.is_active]

    assert len(active) == 1
    assert active[0].rule_id == "provider_openai_key"

    # Verify that competing lower-specificity finding was not silently discarded
    superseded = [s for s in suppressed if s.suppression and s.suppression.reason == "superseded_by_specific_rule"]
    assert len(superseded) >= 1
    assert superseded[0].suppression is not None
    assert superseded[0].suppression.superseded_by_rule_id == "provider_openai_key"


# 11. Component explosion bounds
def test_adversarial_component_explosion():
    from verifyci.secrets.composite import CompositeSignalEngine
    engine = CompositeSignalEngine(max_components=10)
    # Generate 15 context markers on separate lines
    lines = [(i, f"# credential secret auth token {i}") for i in range(1, 16)]
    with pytest.raises(ResourceLimitExceeded) as exc_info:
        engine.extract_context_signals(lines)
    assert exc_info.value.limit_type == "component_count"


# 12. Decoder depth exhaustion bounds
def test_adversarial_decoder_depth_exhaustion():
    from verifyci.secrets.decoder import BoundedDecoder
    decoder = BoundedDecoder(max_depth=2)
    # Create triple-encoded base64
    raw = b"sk-live-9f8a7b6c5d4e1234567890abcdef"
    b1 = base64.b64encode(raw)
    b2 = base64.b64encode(b1)
    b3 = base64.b64encode(b2).decode("utf-8")

    cands = list(decoder.decode_candidates(f'blob = "{b3}"'))
    # Must not exceed depth 2
    max_depth_seen = max((trace.depth for _, _, trace in cands), default=0)
    assert max_depth_seen <= 2


# 13. Candidate-count exhaustion bounds
def test_adversarial_candidate_count_exhaustion():
    detector = SecretDetector()
    ctx = DetectorContext(max_candidates=5)
    # Generate 10 distinct secrets in diff
    lines = "\n".join(f'+key_{i} = "sk-live-9f8a7b6c5d4e123456789{i}"' for i in range(10))
    diff = (
        "diff --git a/src/app.py b/src/app.py\n"
        "--- a/src/app.py\n"
        "+++ b/src/app.py\n"
        f"@@ -1,0 +1,10 @@\n{lines}\n"
    )
    with pytest.raises(ResourceLimitExceeded) as exc_info:
        detector.scan_diff(diff, context=ctx)
    assert exc_info.value.limit_type == "candidate_count"


# 14. Redaction escape attempt (strict zero-leak verification)
def test_adversarial_redaction_escape_attempt():
    detector = SecretDetector()
    synthetic_secret = "sk-live-SECRET999888777666555444333222111"
    diff = _diff(f'secret_assignment = "{synthetic_secret}"')
    findings = detector.scan_diff(diff)
    assert len(findings) >= 1

    for finding in findings:
        # Check every field and serialized representations
        assert_no_secret_leak(finding, synthetic_secret)
        assert_no_secret_leak(finding.evidence_string(), synthetic_secret)
        assert_no_secret_leak(finding.redacted_value, synthetic_secret)
        assert_no_secret_leak(finding.redacted_context, synthetic_secret)
        assert_no_secret_leak(json.dumps(finding, default=str), synthetic_secret)


# 15. Malformed rule configuration fails loudly
def test_adversarial_malformed_rule_configuration():
    # Duplicate rule ID
    rules = [
        SecretRule(rule_id="dup", description="d1", detector_family="f", pattern_strategy=r"a"),
        SecretRule(rule_id="dup", description="d2", detector_family="f", pattern_strategy=r"b"),
    ]
    with pytest.raises(ValueError, match="Duplicate rule_id"):
        RuleRegistry(rules)


# 16. Unknown rule configuration key fails loudly
def test_adversarial_unknown_rule_configuration_key():
    dict_list: list[Mapping[str, Any]] = [{
        "rule_id": "r1",
        "description": "desc",
        "detector_family": "test",
        "pattern_strategy": "pattern",
        "INVALID_UNKNOWN_KEY": "malformed_value",
    }]
    with pytest.raises(ValueError, match="Unknown rule configuration keys"):
        RuleRegistry.from_dict_list(dict_list)


# 17. Anti-circularity verification: detector has no corpus knowledge
def test_adversarial_anti_circularity():
    detector = SecretDetector()
    # Verify detector attributes and rule definitions do not mention benchmark case IDs
    for rule in detector.registry.rules:
        assert "CAP002B" not in rule.rule_id
        assert "cases.jsonl" not in rule.description
        assert "benchmarks" not in str(rule.pattern_strategy)
