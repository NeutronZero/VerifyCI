"""VerifyCI Secret Detection Subsystem (CAP-002B)."""
from verifyci.secrets.contracts import (
    DetectionSignal,
    DetectorContext,
    ResourceLimitExceeded,
    SecretFinding,
    SecretRule,
    SignalCategory,
    SuppressionDecision,
    TransformTrace,
)
from verifyci.secrets.engine import SecretDetector
from verifyci.secrets.hashing import (
    compute_finding_fingerprint,
    compute_rule_config_hash,
    compute_source_hash,
)
from verifyci.secrets.redaction import (
    assert_no_secret_leak,
    redact_context_snippet,
    redact_secret_value,
)
from verifyci.secrets.rules import RuleRegistry, get_default_rules

__all__ = [
    "DetectionSignal",
    "DetectorContext",
    "ResourceLimitExceeded",
    "SecretFinding",
    "SecretRule",
    "SignalCategory",
    "SuppressionDecision",
    "TransformTrace",
    "SecretDetector",
    "RuleRegistry",
    "get_default_rules",
    "redact_secret_value",
    "redact_context_snippet",
    "assert_no_secret_leak",
    "compute_finding_fingerprint",
    "compute_rule_config_hash",
    "compute_source_hash",
]
