"""Qualified names, policy paths, glob matching, and bounded glob coverage.

No function here compiles user input as a regular expression.  The glob
matcher is a tiny translator and the universality check is an explicit
finite-state search over a small abstract alphabet.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from verifyci.contracts.model import glob_match


class NameError(ValueError):
    pass


def normalize_repo_path(path: str) -> str:
    p = str(path).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def is_safe_repo_path(path: str) -> bool:
    if not path or "\x00" in path or path.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:", path):
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def validate_glob_pattern(pattern: str, *, allow_leading_slash: bool = False) -> str:
    """Validate a policy glob and return its normalized form."""
    if not isinstance(pattern, str) or not pattern:
        raise NameError("glob pattern must be a non-empty string")
    if "\x00" in pattern or "\\" in pattern:
        raise NameError("glob pattern contains a forbidden escape")
    if any(ch in pattern for ch in "![]"):
        raise NameError("glob pattern contains unsupported syntax")
    p = pattern
    if p.startswith("/"):
        if not allow_leading_slash:
            raise NameError("glob pattern must be repository-relative")
        p = p[1:]
    if p.endswith("/"):
        raise NameError("glob pattern must not end with a separator")
    if "//" in p:
        raise NameError("glob pattern contains an empty segment")
    for segment in p.split("/"):
        if segment in ("", ".", ".."):
            raise NameError("glob pattern contains a non-canonical segment")
    return p


def normalize_module_name(path: str, source_roots: Sequence[str] = ()) -> str:
    p = normalize_repo_path(path)
    for root in sorted(source_roots, key=len, reverse=True):
        r = root.strip("/")
        if r in ("", "."):
            continue
        if p == r or p.startswith(r + "/"):
            p = p[len(r):].lstrip("/")
            break
    if p.endswith(".py"):
        p = p[:-3]
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    elif p == "__init__":
        p = ""
    return p.replace("/", ".")


def qualify(module: str, qualname: str) -> str:
    return f"{module}:{qualname}" if module else qualname


def parse_qualified_name(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise NameError(f"qualified name must be module:qualname: {value!r}")
    module, qualname = value.split(":", 1)
    if not module or not qualname:
        raise NameError(f"qualified name must have non-empty module and qualname: {value!r}")
    return module, qualname


_VOLATILE_IDENTITY_KEYS = frozenset(
    {
        "line",
        "line_number",
        "start_line",
        "end_line",
        "start",
        "end",
        "span",
        "base_span",
        "head_span",
        "reference_count",
    }
)


def normalize_evidence_identity(value: Any) -> Any:
    """Strip rebase-sensitive locations from a waiver evidence identity."""
    if isinstance(value, Mapping):
        return {
            key: normalize_evidence_identity(item)
            for key, item in value.items()
            if key not in _VOLATILE_IDENTITY_KEYS
        }
    if isinstance(value, (list, tuple)):
        return [normalize_evidence_identity(item) for item in value]
    return value


def stable_finding_fingerprint(
    *,
    check_id: str,
    defect_id: str,
    defect_semantics_version: int,
    path: str,
    symbol: str = "",
    evidence_identity: object = None,
) -> str:
    """SHA-256 over canonical, rebase-stable finding identity fields."""
    payload = {
        "check_id": check_id,
        "defect_id": defect_id,
        "defect_semantics_version": defect_semantics_version,
        "path": normalize_repo_path(path),
        "symbol": symbol,
        "evidence_identity": normalize_evidence_identity(evidence_identity),
    }
    raw = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    return "sha256:" + sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Glob union universality
# ---------------------------------------------------------------------------

_OTHER = "\x00OTHER"


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # literal | star | globstar | question | slash
    value: str = ""


def _tokenize(pattern: str) -> tuple[_Token, ...]:
    tokens: list[_Token] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                tokens.append(_Token("globstar"))
                i += 2
                continue
            tokens.append(_Token("star"))
        elif ch == "?":
            tokens.append(_Token("question"))
        elif ch == "/":
            tokens.append(_Token("slash"))
        else:
            tokens.append(_Token("literal", ch))
        i += 1
    return tuple(tokens)


def _epsilon_closure(states: Iterable[tuple[int, int]], token_lists: Sequence[Sequence[_Token]]) -> frozenset[tuple[int, int]]:
    stack = list(states)
    seen = set(states)
    while stack:
        pattern_id, index = stack.pop()
        tokens = token_lists[pattern_id]
        if index >= len(tokens):
            continue
        token = tokens[index]
        if token.kind in ("star", "globstar"):
            nxt = (pattern_id, index + 1)
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return frozenset(seen)


def _step(
    states: Iterable[tuple[int, int]],
    symbol: str,
    token_lists: Sequence[Sequence[_Token]],
) -> frozenset[tuple[int, int]]:
    out: set[tuple[int, int]] = set()
    for pattern_id, index in states:
        tokens = token_lists[pattern_id]
        if index >= len(tokens):
            continue
        token = tokens[index]
        if token.kind == "literal":
            if symbol == token.value:
                out.add((pattern_id, index + 1))
        elif token.kind == "slash":
            if symbol == "/":
                out.add((pattern_id, index + 1))
        elif token.kind == "question":
            if symbol != "/":
                out.add((pattern_id, index + 1))
        elif token.kind == "star":
            if symbol != "/":
                out.add((pattern_id, index))
        elif token.kind == "globstar":
            out.add((pattern_id, index))
    return _epsilon_closure(out, token_lists)


def glob_union_is_universal(patterns: Sequence[str]) -> bool:
    """Return True iff the union matches every valid non-empty relative path.

    The check is exact for the supported glob language over a finite abstract
    alphabet (all literal characters plus one OTHER symbol and '/').  It is
    bounded by the number of reachable NFA subsets, so malformed or enormous
    pattern sets can be rejected deterministically by the caller's budget.
    """
    if not patterns:
        return False
    token_lists = [_tokenize(validate_glob_pattern(p)) for p in patterns]
    starts = _epsilon_closure([(i, 0) for i in range(len(token_lists))], token_lists)
    alphabet = {"/", _OTHER}
    for tokens in token_lists:
        for token in tokens:
            if token.kind == "literal":
                alphabet.add(token.value)

    # Valid-path DFA states: START, SEG, SLASH, DEAD.  Accepting: SEG.
    def path_step(state: str, symbol: str) -> str:
        if state == "START":
            return "SEG" if symbol != "/" else "DEAD"
        if state == "SEG":
            return "SEG" if symbol != "/" else "SLASH"
        if state == "SLASH":
            return "SEG" if symbol != "/" else "DEAD"
        return "DEAD"

    queue: deque[tuple[frozenset[tuple[int, int]], str]] = deque()
    start = (starts, "START")
    queue.append(start)
    seen = {start}
    while queue:
        nfa_states, path_state = queue.popleft()
        accepting = any(index >= len(token_lists[pid]) for pid, index in nfa_states)
        if path_state == "SEG" and not accepting:
            return False
        for symbol in alphabet:
            next_nfa = _step(nfa_states, symbol, token_lists)
            if not next_nfa:
                continue
            next_path = path_step(path_state, symbol)
            if next_path == "DEAD":
                continue
            node = (next_nfa, next_path)
            if node not in seen:
                seen.add(node)
                queue.append(node)
    return True


def path_matches_any(patterns: Sequence[str], value: str) -> bool:
    return any(glob_match(p, value, kind="path") for p in patterns)


def symbol_matches_any(patterns: Sequence[str], value: str) -> bool:
    return any(glob_match(p, value, kind="symbol") for p in patterns)


__all__ = [
    "NameError",
    "glob_union_is_universal",
    "normalize_module_name",
    "normalize_repo_path",
    "parse_qualified_name",
    "path_matches_any",
    "qualify",
    "stable_finding_fingerprint",
    "symbol_matches_any",
    "validate_glob_pattern",
]
