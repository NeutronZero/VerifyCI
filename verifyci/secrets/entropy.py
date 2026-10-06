"""Information-theoretic entropy calculation and false-positive discriminators."""
from __future__ import annotations

import collections
import math
import re

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")

_PLACEHOLDER_SUBSTRINGS = (
    "YOUR_API_KEY",
    "YOUR_SECRET",
    "YOUR_PASSWORD",
    "ENTER_SECRET",
    "ENTER_KEY",
    "INSERT_KEY",
    "TODO_INSERT",
    "REPLACE_ME",
    "CHANGEME",
    "EXAMPLE_KEY",
    "EXAMPLE_SECRET",
    "DUMMY_KEY",
    "MOCK_TOKEN",
    "TEST_TOKEN_000",
)

_ENV_LOOKUP_PATTERNS = (
    re.compile(r"""(?:os\.environ(?:\.get|\[)|os\.getenv)\s*\("""),
    re.compile(r"""(?:config|settings|env_manager|credentials)\.get\s*\("""),
    re.compile(r"""(?:get_password|get_secret|load_token|read_credentials)\s*\("""),
)

_DOTTED_ASSIGNMENT_RE = re.compile(
    r"""^\s*(?:self|[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*"""
    r"""(?:[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*\s*\()"""
)


def shannon_entropy(s: str) -> float:
    """Compute base-2 Shannon entropy of string."""
    if not s:
        return 0.0
    length = len(s)
    counts = collections.Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def char_diversity(s: str) -> float:
    """Compute ratio of unique characters to length."""
    if not s:
        return 0.0
    return len(set(s)) / len(s)


def is_uuid(s: str) -> bool:
    """True if string matches standard UUID form."""
    clean = s.strip().strip("'\"")
    return _UUID_RE.match(clean) is not None


def is_git_or_hex_hash(s: str) -> bool:
    """True if string is purely a standard hex hash (e.g. git commit SHA, sha256, md5)
    without provider prefixes or mixed cases.
    """
    clean = s.strip().strip("'\"")
    if not _HEX_HASH_RE.match(clean):
        return False
    # If it's uniform lowercase or uniform uppercase hex and of standard lengths (32, 40, 64)
    if len(clean) in (32, 40, 64) and (clean.islower() or clean.isupper() or clean.isdigit()):
        return True
    return False


def is_well_known_placeholder(s: str) -> bool:
    """True if string represents a documented template placeholder."""
    clean = s.strip().strip("'\"").upper()
    if clean in ("CHANGEME", "DUMMY", "EXAMPLE", "PASSWORD", "SECRET", "TOKEN", "ADMIN"):
        return True
    for p in _PLACEHOLDER_SUBSTRINGS:
        if p in clean:
            return True
    if re.fullmatch(r"0{8,}|x{8,}|[a-f0-9]{0,4}00000000[a-f0-9]{0,4}", clean.lower()):
        return True
    return False


def is_env_or_config_lookup(line: str) -> bool:
    """True if line fetches credentials dynamically from runtime environment or config."""
    for pat in _ENV_LOOKUP_PATTERNS:
        if pat.search(line):
            return True
    return False


def is_dotted_attribute_wiring(line: str) -> bool:
    """True if line is dotted object attribute wiring rather than a secret literal.
    
    e.g. self.password = user_provided_password, secret_key = config.SECRET_KEY_NAME
    """
    stripped = line.strip()
    if _DOTTED_ASSIGNMENT_RE.match(stripped):
        return True
    # Assignment where RHS is dotted lookup like config.KEY or creds.token
    if "=" in stripped or ":" in stripped:
        parts = re.split(r"[:=]", stripped, maxsplit=1)
        if len(parts) == 2:
            lhs = parts[0].strip()
            rhs = parts[1].strip().rstrip(";,").strip()
            # Dotted LHS (self.password = ...)
            if "." in lhs and not lhs.startswith(("'", '"')):
                return True
            # Dotted RHS without quotes (password = config.SECRET)
            if "." in rhs and not rhs.startswith(("'", '"')) and not rhs.startswith(("http://", "https://", "postgres://", "mysql://", "mongodb://")):
                if "(" in rhs or ")" in rhs or re.match(r"^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$", rhs):
                    return True
    return False
