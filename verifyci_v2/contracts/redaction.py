"""Secret redaction for pre-egress code slices (spec §3.6D, §5).

Replaces matched credential patterns, credential-named assignments, and
high-entropy quoted blobs with ``<REDACTED_SECRET_N>`` placeholders before
any code slice leaves the host for a BYO-AI endpoint.

Single source of truth for the whole engine. This module is a leaf: it imports
nothing from ``verifyci_v2``, so every other layer may depend on it without
creating a cycle. Deterministic: the same input always yields the same
placeholder numbering, independent of rule iteration order.
"""

from __future__ import annotations

import math
import re

from msgspec import Struct

# Minimum quoted-blob length considered for entropy-gated redaction. Below this
# a match is more likely prose, a path, or an ordinary identifier.
_MIN_BLOB_LEN = 24

# Minimum Shannon entropy (bits per character) for an unnamed quoted blob. A
# generated credential sits near 4.0; hex digests, base64 payloads, and
# dictionary words cluster lower.
_BLOB_ENTROPY_FLOOR = 3.7


class RedactionResult(Struct, frozen=True):
    """Redacted text plus metadata about what was removed."""

    redacted_text: str
    redacted_count: int
    placeholders: tuple[str, ...] = ()


def shannon_entropy(text: str) -> float:
    """Computes the Shannon entropy H(X) in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _has_long_sequential_run(value: str, run_length: int = 12) -> bool:
    """True when `value` contains an ascending or descending run of `run_length`.

    Alphabet filler such as "abcdefghijklmnopqrstuvwxyz" is not a credential.
    """
    for start in range(len(value) - run_length + 1):
        window = value[start : start + run_length]
        ascending = all(
            ord(window[i + 1]) - ord(window[i]) == 1 for i in range(run_length - 1)
        )
        descending = all(
            ord(window[i]) - ord(window[i + 1]) == 1 for i in range(run_length - 1)
        )
        if ascending or descending:
            return True
    return False


# Rules that redact on shape alone. Each carries the span to replace in group
# `val`, or the whole match when `val` is absent.
_SHAPE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # AWS access key IDs (AKIA/ASIA/ABIA/ACCA) and other long-lived key ids.
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    # GitHub personal/OAuth/user/server tokens and fine-grained PATs.
    (
        "GITHUB_PAT",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{82})\b"
        ),
    ),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,120}\b")),
    ("STRIPE_LIVE_KEY", re.compile(r"\b[rs]k_live_[0-9a-zA-Z]{16,99}\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{30,50}\b")),
    ("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,120}\b")),
    # PEM private key blocks, header through footer.
    (
        "PRIVATE_KEY_BLOCK",
        re.compile(
            r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----.*?"
            r"-----END (?:[A-Z ]+)?PRIVATE KEY-----",
            re.S,
        ),
    ),
    # Connection strings carrying an inline credential. The scheme allowlist
    # keeps ordinary `https://host:port/path` URIs out of the results, and the
    # password segment may itself contain `@`, `:` and `/`.
    (
        "CONNECTION_STRING_CREDENTIAL",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb\+srv|mongodb|redis|rediss|"
            r"amqps?|mssql|sqlserver|ftps?|ssh|ldap|jdbc):\/\/"
            r"[^\s:/@\"'()\[\]{}]{1,64}:[^\s\"'()\[\]]{4,128}@[^\s\"'()\[\]]{3,}"
        ),
    ),
    # JSON Web Tokens: base64url header (always starts "eyJ" for `{"`) + payload
    # + signature.
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    # Credential-named assignment: the identifier itself is preserved, only the
    # value is replaced.
    (
        "CREDENTIAL_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?P<key>password|passwd|pwd|secret|token|api[_-]?key|apikey|"
            r"access[_-]?key|private[_-]?key|credential|passphrase|client[_-]?secret|"
            r"auth[_-]?token)\s*[:=]\s*[\"']?(?P<val>[^\s\"',;)]{6,})[\"']?"
        ),
    ),
    # Unnamed quoted blob, gated on entropy and on the absence of alphabet
    # filler. Catches bare keys and tokens that carry no recognizable prefix.
    (
        "ENTROPY_BLOB",
        re.compile(r"[\"'](?P<val>[A-Za-z0-9_\-+/=]{%d,})[\"']" % _MIN_BLOB_LEN),
    ),
)


def _is_alphabet_filler(value: str) -> bool:
    """True when the value is padded sequence rather than a generated secret."""
    return _has_long_sequential_run(value.lower())


def _collect_spans(text: str) -> list[tuple[int, int]]:
    """Return non-overlapping spans to redact, in ascending offset order."""
    spans: list[tuple[int, int]] = []
    for _rule_name, pattern in _SHAPE_RULES:
        for match in pattern.finditer(text):
            named = match.groupdict()
            # Every rule exposes the credential itself as `val` where one exists.
            if named.get("val") is not None:
                start, end = match.start("val"), match.end("val")
                candidate = match.group("val")
                if candidate.startswith("<REDACTED_SECRET_"):
                    continue
                # Entropy-gated and filler-gated rules only redact values that
                # actually look generated.
                if _rule_name == "ENTROPY_BLOB":
                    if _is_alphabet_filler(candidate):
                        continue
                    if shannon_entropy(candidate) < _BLOB_ENTROPY_FLOOR:
                        continue
            else:
                start, end = match.span()
            if end > start:
                spans.append((start, end))

    # Merge overlapping spans so a credential matched by two rules yields one
    # placeholder, and ordering never depends on rule iteration order.
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def redact_secrets(text: str) -> RedactionResult:
    """Return a redacted copy of `text` plus metadata.

    Deterministic and idempotent: redacting an already-redacted string finds no
    spans and returns it unchanged.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    spans = _collect_spans(text)
    if not spans:
        return RedactionResult(redacted_text=text, redacted_count=0, placeholders=())
    out: list[str] = []
    placeholders: list[str] = []
    idx = 0
    for n, (start, end) in enumerate(spans, start=1):
        out.append(text[idx:start])
        ph = f"<REDACTED_SECRET_{n}>"
        placeholders.append(ph)
        out.append(ph)
        idx = end
    out.append(text[idx:])
    return RedactionResult(
        redacted_text="".join(out),
        redacted_count=len(spans),
        placeholders=tuple(placeholders),
    )


def redact_in_place_mapping(text: str) -> str:
    """Convenience: returns only the redacted text."""
    return redact_secrets(text).redacted_text