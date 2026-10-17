"""Canonical hashing, digest computation, and secret redaction utilities."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Sequence

_SECRET_REDACTION_DOMAIN = "verifyci.redaction"
_REDACTION_MASK_PATTERN = r"\[REDACTED_SECRET:[a-f0-9]{8}\]"


def canonical_json_dumps(data: Any) -> str:
    """Serialize data into RFC 8785 JSON canonical string."""
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def content_digest_hex(content: str | bytes, domain: str = "verifyci.core") -> str:
    """Compute deterministic domain-separated SHA-256 digest."""
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
    else:
        content_bytes = content

    hasher = hashlib.sha256()
    hasher.update(f"{domain}:".encode("utf-8"))
    hasher.update(content_bytes)
    return hasher.hexdigest()


def redact_token(token: str) -> str:
    """Redact a sensitive token into a deterministic masked tag.

    Example: 'ghp_abc123' -> '[REDACTED_SECRET:4f2a91b0]'
    The plaintext token is never exposed in logs or findings.
    """
    token_digest = content_digest_hex(token, domain=_SECRET_REDACTION_DOMAIN)[:8]
    return f"[REDACTED_SECRET:{token_digest}]"


def redact_secrets(text: str, patterns: Sequence[re.Pattern[str]]) -> str:
    """Replace all sensitive patterns in text with deterministic redaction tags."""
    redacted = text
    for pattern in patterns:
        def _replace(match: re.Match[str]) -> str:
            val = match.group(0)
            return redact_token(val)
        redacted = pattern.sub(_replace, redacted)
    return redacted
