"""Deterministic clean-room rule registry and built-in rules for VerifyCI (CAP-002B)."""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from verifyci.secrets.contracts import SecretRule

# ---------------------------------------------------------------------------
# Clean-Room Pattern Strategies (independently authored)
# ---------------------------------------------------------------------------

# Provider Token Patterns (Value-First: NO variable name required)
_OPENAI_TOKEN_RE = re.compile(r"""\b(?:sk-live-[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{12,})\b""")
_STRIPE_KEY_RE = re.compile(r"""\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{14,}\b""")
_GITHUB_TOKEN_RE = re.compile(r"""\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b""")
_SLACK_TOKEN_RE = re.compile(r"""\bxox[baprs]-[0-9a-zA-Z-]{18,}\b""")
_AWS_ACCESS_KEY_RE = re.compile(r"""\b(?:AKIA|ASIA|AROA)[0-9A-Z]{16}\b""")
_GOOGLE_API_KEY_RE = re.compile(r"""\bAIza[0-9A-Za-z_-]{35}\b""")

# Cryptographic and Private Key Headers
_PEM_PRIVATE_KEY_RE = re.compile(
    r"""-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"""
)

# JWT Tokens (Tripartite header.payload.signature)
_JWT_TOKEN_RE = re.compile(
    r"""\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{12,}\b"""
)

# Credential-bearing connection strings
_CONN_STRING_RE = re.compile(
    r"""(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/]+:[^\s@/]{3,}@[^\s/]+"""
)

# Keyword assignments (Quoted literals)
_KEYWORD_NAMES = (
    r"(?:[A-Za-z0-9_]{0,32}[_-])?"
    r"(?:password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key)"
    r"(?:[_-][A-Za-z0-9_]{1,32})?"
)
_KEYWORD_QUOTED_RE = re.compile(
    r"""(?i)\b""" + _KEYWORD_NAMES + r"""\s*[:=]\s*['"]([^'"]{3,})['"]"""
)

# Unquoted assignments
_UNQUOTED_ASSIGNMENT_RE = re.compile(
    r"""(?i)(?<!\.)\b""" + _KEYWORD_NAMES + r"""\s*[:=]\s*([^\s().\"'`#;,]{12,})(?=\s*(?:[;,#]|$))"""
)

# Short unquoted AWS access key family (8+ chars)
_SHORT_UNQUOTED_AWS_RE = re.compile(
    r"""(?i)(?<!\.)(?:AWS_SECRET_ACCESS_KEY|AWS_SECRET_KEY)\s*[:=]\s*([^\s().\"'`#;,]{8,})(?=\s*(?:[;,#]|$))"""
)

# JSON colon form: {"api_key": "..."}
_JSON_COLON_RE = re.compile(
    r"""(?i)["']""" + _KEYWORD_NAMES + r"""["']\s*:\s*["']([^"']{3,})["']"""
)

# YAML unquoted form: db_password: secret-value
_YAML_UNQUOTED_RE = re.compile(
    r"""(?i)^\s*""" + _KEYWORD_NAMES + r""":\s*([^\s().\"'`#;,]{8,})(?=\s*(?:[;,#]|$))"""
)


def get_default_rules() -> list[SecretRule]:
    """Instantiate the canonical clean-room VerifyCI secret rules."""
    return [
        # 1. Cryptographic Private Key (highest specificity: 95)
        SecretRule(
            rule_id="crypto_private_key",
            description="Cryptographic private key block (PEM/OpenSSH)",
            detector_family="private_key",
            pattern_strategy=_PEM_PRIVATE_KEY_RE,
            keywords=(),  # Eligible on all lines
            specificity=95,
            confidence=1.0,
            min_length=30,
        ),
        # 2. Provider Tokens (specificity: 90)
        SecretRule(
            rule_id="provider_openai_key",
            description="OpenAI API token (sk-live/sk-proj prefix)",
            detector_family="provider_token",
            pattern_strategy=_OPENAI_TOKEN_RE,
            keywords=(),  # Value-first, identifier-independent!
            specificity=90,
            confidence=0.99,
            min_length=20,
        ),
        SecretRule(
            rule_id="provider_stripe_key",
            description="Stripe secret or restricted key",
            detector_family="provider_token",
            pattern_strategy=_STRIPE_KEY_RE,
            keywords=(),
            specificity=90,
            confidence=0.99,
            min_length=16,
        ),
        SecretRule(
            rule_id="provider_github_token",
            description="GitHub personal access or OAuth token",
            detector_family="provider_token",
            pattern_strategy=_GITHUB_TOKEN_RE,
            keywords=(),
            specificity=90,
            confidence=0.99,
            min_length=20,
        ),
        SecretRule(
            rule_id="provider_slack_token",
            description="Slack bot/user API token",
            detector_family="provider_token",
            pattern_strategy=_SLACK_TOKEN_RE,
            keywords=(),
            specificity=90,
            confidence=0.99,
            min_length=20,
        ),
        SecretRule(
            rule_id="provider_aws_access_key",
            description="AWS Access Key ID credential",
            detector_family="provider_token",
            pattern_strategy=_AWS_ACCESS_KEY_RE,
            keywords=(),
            specificity=90,
            confidence=0.95,
            min_length=20,
        ),
        SecretRule(
            rule_id="provider_google_api_key",
            description="Google Cloud API key (AIza prefix)",
            detector_family="provider_token",
            pattern_strategy=_GOOGLE_API_KEY_RE,
            keywords=(),
            specificity=90,
            confidence=0.95,
            min_length=39,
        ),
        # 3. JWT Token (specificity: 85)
        SecretRule(
            rule_id="structured_jwt_token",
            description="JSON Web Token (JWT) bearer credential",
            detector_family="jwt",
            pattern_strategy=_JWT_TOKEN_RE,
            keywords=(),
            specificity=85,
            confidence=0.95,
            min_length=30,
        ),
        # 4. Connection String (specificity: 80)
        SecretRule(
            rule_id="credential_connection_string",
            description="Database/Broker URI containing username and password",
            detector_family="connection_string",
            pattern_strategy=_CONN_STRING_RE,
            keywords=(),
            specificity=80,
            confidence=0.95,
            min_length=15,
        ),
        # 5. Generic Keyword Quoted Assignment (specificity: 60)
        SecretRule(
            rule_id="keyword_quoted_assignment",
            description="Credential keyword assigned a quoted literal",
            detector_family="keyword_assignment",
            pattern_strategy=_KEYWORD_QUOTED_RE,
            keywords=("password", "passwd", "secret", "api", "auth", "token", "private", "key"),
            specificity=60,
            confidence=0.90,
            min_length=3,
            max_length=200_000,
        ),
        # 6. JSON Colon Form (specificity: 60)
        SecretRule(
            rule_id="json_colon_secret",
            description="JSON key-value pair assigning a credential",
            detector_family="keyword_assignment",
            pattern_strategy=_JSON_COLON_RE,
            keywords=("password", "passwd", "secret", "api", "auth", "token", "private", "key"),
            specificity=60,
            confidence=0.90,
            min_length=3,
        ),
        # 7. Short Unquoted AWS Secret (specificity: 55)
        SecretRule(
            rule_id="short_unquoted_aws_key",
            description="AWS Secret Key assigned unquoted value (8+ chars)",
            detector_family="keyword_assignment",
            pattern_strategy=_SHORT_UNQUOTED_AWS_RE,
            keywords=("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY"),
            specificity=55,
            confidence=0.90,
            min_length=8,
        ),
        # 8. Unquoted Assignment (specificity: 50)
        SecretRule(
            rule_id="keyword_unquoted_assignment",
            description="Credential keyword assigned an unquoted literal (12+ chars)",
            detector_family="keyword_assignment",
            pattern_strategy=_UNQUOTED_ASSIGNMENT_RE,
            keywords=("password", "passwd", "secret", "api", "auth", "token", "private", "key"),
            specificity=50,
            confidence=0.85,
            min_length=12,
        ),
        # 9. YAML Unquoted Form (specificity: 50)
        SecretRule(
            rule_id="yaml_unquoted_secret",
            description="YAML mapping assigning unquoted credential",
            detector_family="keyword_assignment",
            pattern_strategy=_YAML_UNQUOTED_RE,
            keywords=("password", "passwd", "secret", "api", "auth", "token", "private", "key"),
            specificity=50,
            confidence=0.85,
            min_length=8,
        ),
        # 10. Composite Contextual Secret (specificity: 40)
        SecretRule(
            rule_id="composite_entropy_secret",
            description="High-entropy token supported by nearby credential context",
            detector_family="composite",
            pattern_strategy=re.compile(r"""['"]([A-Za-z0-9+/=_-]{24,})['"]"""),
            keywords=(),
            specificity=40,
            confidence=0.85,
            entropy_threshold=3.5,
            min_length=24,
            requires_supporting_context=True,
        ),
    ]


class RuleRegistry:
    """Immutable, validated registry of secret detection rules."""

    ALLOWED_RULE_KEYS = frozenset({
        "rule_id",
        "description",
        "detector_family",
        "pattern_strategy",
        "keywords",
        "path_patterns",
        "excluded_path_patterns",
        "confidence",
        "specificity",
        "supporting_signals",
        "entropy_threshold",
        "min_length",
        "max_length",
        "requires_supporting_context",
    })

    def __init__(self, rules: Sequence[SecretRule]):
        self._rules_by_id: dict[str, SecretRule] = {}
        self._ordered_rules: list[SecretRule] = []

        seen_ids = set()
        for r in rules:
            if not isinstance(r, SecretRule):
                raise TypeError(f"Expected SecretRule instance, got {type(r)}")
            if not r.rule_id:
                raise ValueError("SecretRule must have non-empty rule_id")
            if r.rule_id in seen_ids:
                raise ValueError(f"Duplicate rule_id detected: {r.rule_id!r}")
            seen_ids.add(r.rule_id)
            self._rules_by_id[r.rule_id] = r
            self._ordered_rules.append(r)

        # Deterministic sorting by specificity descending, then rule_id ascending
        self._ordered_rules.sort(key=lambda x: (-x.specificity, x.rule_id))
        self._rules_tuple = tuple(self._ordered_rules)

    @classmethod
    def from_dict_list(cls, dicts: list[Mapping[str, Any]]) -> RuleRegistry:
        """Construct registry from dictionaries, failing loudly on unknown keys."""
        rules = []
        for d in dicts:
            unknown = set(d.keys()) - cls.ALLOWED_RULE_KEYS
            if unknown:
                raise ValueError(f"Unknown rule configuration keys: {sorted(unknown)}")
            pat = d["pattern_strategy"]
            if isinstance(pat, str):
                pat = re.compile(pat)
            rule = SecretRule(
                rule_id=d["rule_id"],
                description=d.get("description", ""),
                detector_family=d.get("detector_family", "custom"),
                pattern_strategy=pat,
                keywords=tuple(d.get("keywords", ())),
                path_patterns=tuple(d.get("path_patterns", ())),
                excluded_path_patterns=tuple(d.get("excluded_path_patterns", ())),
                confidence=float(d.get("confidence", 0.95)),
                specificity=int(d.get("specificity", 50)),
                supporting_signals=tuple(d.get("supporting_signals", ())),
                entropy_threshold=d.get("entropy_threshold"),
                min_length=int(d.get("min_length", 6)),
                max_length=int(d.get("max_length", 4096)),
                requires_supporting_context=bool(d.get("requires_supporting_context", False)),
            )
            rules.append(rule)
        return cls(rules)

    @property
    def rules(self) -> tuple[SecretRule, ...]:
        return self._rules_tuple

    def get_rule(self, rule_id: str) -> SecretRule | None:
        return self._rules_by_id.get(rule_id)

    def __iter__(self):
        return iter(self._rules_tuple)

    def __len__(self) -> int:
        return len(self._rules_tuple)
