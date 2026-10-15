"""Secret redaction for pre-egress code slices (spec §3.6D, §5).

Replaces high-entropy strings and matched credential patterns with
``<REDACTED_SECRET_N>`` placeholders before any code slice leaves the
host for a BYO-AI endpoint. Deterministic: the same input always yields the
same placeholder numbering.
"""

from __future__ import annotations

import re
from msgspec import Struct


class RedactionResult(Struct, frozen=True):
    redacted_text: str
    redacted_count: int
    placeholders: tuple[str, ...] = ()


_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),  # GitHub PAT
    re.compile(r"gho_[A-Za-z0-9]{36,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI / Stripe
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    # JWT-ish
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # key=value or key: value credentials
    re.compile(
        r"(?i)(?P<key>api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd|"
        r"private[_-]?key|client[_-]?secret)\s*[:=]\s*[\"']?(?P<val>[A-Za-z0-9_\-./+=]{8,})[\"']?",
    ),
    # generic high-entropy quoted blob >= 24 chars containing both cases/digits
    re.compile(r"[\"'](?P<val>[A-Za-z0-9_\-+/=]{24,})[\"']"),
)


def _collect_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pat in _PATTERNS:
        for m in pat.finditer(text):
            # prefer named 'val' group if present
            g = m.groupdict().get("val")
            if g is not None:
                start = m.start("val")
                end = m.end("val")
            else:
                start, end = m.span()
            spans.append((start, end))
    # sort and de-overlap
    spans.sort()
    out: list[tuple[int, int]] = []
    last_end = -1
    for s, e in spans:
        if s >= last_end:
            out.append((s, e))
            last_end = e
        elif e > last_end:
            # overlapping: keep the longer of adjacent? skip new
            pass
    return out


def redact_secrets(text: str) -> RedactionResult:
    """Return a redacted copy of ``text`` plus metadata."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    spans = _collect_spans(text)
    if not spans:
        return RedactionResult(redacted_text=text, redacted_count=0, placeholders=())
    # build
    out: list[str] = []
    idx = 0
    placeholders: list[str] = []
    n = 0
    for s, e in spans:
        out.append(text[idx:s])
        n += 1
        ph = f"<REDACTED_SECRET_{n}>"
        placeholders.append(ph)
        out.append(ph)
        idx = e
    out.append(text[idx:])
    return RedactionResult(
        redacted_text="".join(out),
        redacted_count=n,
        placeholders=tuple(placeholders),
    )


def redact_in_place_mapping(text: str) -> str:
    """Convenience: returns only the redacted text."""
    return redact_secrets(text).redacted_text
