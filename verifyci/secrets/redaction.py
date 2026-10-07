"""Strict Redaction Hard Boundary for VerifyCI secret detection."""
from __future__ import annotations

import hashlib
import json
from typing import Any


def redact_secret_value(val: str) -> str:
    """Mask a raw secret into a safe, non-reversible, redacted representation.

    Exact guarantee: the output reveals only the secret's character length
    and a SHA-256 digest of its UTF-8 bytes, and carries zero raw plaintext
    characters (no prefix/suffix fragments). SHA-256 is preimage- and
    second-preimage-resistant, so the secret cannot be recovered from the
    digest except by dictionary/brute-force guess-and-compare against
    already-known candidates; short or low-entropy secrets remain
    guessable, which no redaction format can prevent.
    """
    if not val:
        return "[REDACTED:EMPTY]"
    length = len(val)
    digest = hashlib.sha256(val.encode("utf-8")).hexdigest()
    return f"[REDACTED:len={length}:sha256={digest}]"


#: Minimum contiguous run treated as a fragment leak. Runs of 8+ chars
#: carry enough entropy to be identifying; shorter runs are only checked
#: via the full-string match to avoid flagging coincidental overlaps.
_FRAGMENT_LEN = 8
#: Upper bound on fragment windows checked per assertion, keeping the
#: check linear for very long secrets (evenly sampled windows).
_MAX_FRAGMENT_WINDOWS = 64


def _leak_windows(raw_secret: str) -> list[str]:
    """Contiguous fragments of raw_secret that must not appear anywhere."""
    n = len(raw_secret)
    if n < _FRAGMENT_LEN:
        return [raw_secret] if raw_secret else []
    if n <= _MAX_FRAGMENT_WINDOWS + _FRAGMENT_LEN:
        return [raw_secret[i:i + _FRAGMENT_LEN] for i in range(n - _FRAGMENT_LEN + 1)]
    step = max(1, n // _MAX_FRAGMENT_WINDOWS)
    return [raw_secret[i:i + _FRAGMENT_LEN] for i in range(0, n - _FRAGMENT_LEN + 1, step)]


def _contains_leak(haystack: str, windows: list[str]) -> str | None:
    """Return the first leaked window found in haystack, else None."""
    for w in windows:
        if w and w in haystack:
            return w
    return None


def redact_context_snippet(line: str, span: tuple[int, int]) -> str:
    """Replace sensitive span within a context line with a safe marker."""
    if not line:
        return ""
    start, end = span
    start = max(0, min(start, len(line)))
    end = max(start, min(end, len(line)))
    return line[:start] + "[REDACTED]" + line[end:]


def assert_no_secret_leak(obj: Any, raw_secret: str) -> None:
    """Hard boundary assertion: recursively verify that raw_secret never appears
    in any serialized or string representation of obj.

    Catches both full-string leaks (raw_secret present verbatim) and
    fragment leaks (any contiguous run of 8+ secret characters present
    verbatim; evenly sampled windows bound the check for very long
    secrets). Secrets shorter than 8 chars are checked full-string-only:
    flagging shorter runs would fire on coincidental overlaps.
    """
    if not raw_secret or len(raw_secret) < 3:
        return
    windows = _leak_windows(raw_secret)

    def _check(val: Any) -> None:
        if isinstance(val, str):
            leaked = _contains_leak(val, windows)
            if leaked is not None:
                raise AssertionError(f"Redaction violation! Raw secret fragment leaked into: {val[:50]}...")
        elif isinstance(val, bytes):
            if raw_secret.encode("utf-8") in val:
                raise AssertionError("Redaction violation! Raw secret bytes leaked into bytes object.")
            try:
                decoded = val.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return
            leaked = _contains_leak(decoded, windows)
            if leaked is not None:
                raise AssertionError("Redaction violation! Raw secret fragment leaked into bytes object.")
        elif isinstance(val, dict):
            for k, v in val.items():
                _check(k)
                _check(v)
        elif isinstance(val, (list, tuple, set)):
            for item in val:
                _check(item)
        elif hasattr(val, "__dict__"):
            _check(val.__dict__)

    _check(obj)
    # Also test JSON serialization if serializable
    try:
        serialized = json.dumps(obj, default=str)
        leaked = _contains_leak(serialized, windows)
        if leaked is not None:
            raise AssertionError("Redaction violation! Raw secret fragment leaked into serialized JSON.")
    except (TypeError, ValueError):
        pass
