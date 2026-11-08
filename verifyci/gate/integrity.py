"""Built-in gate-integrity paths and the active-CODEOWNERS evaluator."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Sequence

from verifyci.contracts.model import DiffEntry
from verifyci.contracts.names import normalize_repo_path
from verifyci.scm.git import GitRepo


PROTECTED_SUBTREES: tuple[str, ...] = (
    ".verifyci/",
    ".github/workflows/",
    ".github/actions/",
)
PROTECTED_FILES: tuple[str, ...] = (
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
)
CODEOWNERS_LOOKUP: tuple[str, ...] = (
    ".github/CODEOWNERS",
    "CODEOWNERS",
    "docs/CODEOWNERS",
)
POLICY_PATH = ".verifyci/policy.toml"
MAX_CODEOWNERS_BYTES = 3 * 1024 * 1024


def _segments(path: str) -> tuple[str, ...]:
    return tuple(part for part in normalize_repo_path(path).strip("/").split("/") if part)


def is_protected_path(path: str) -> bool:
    p = normalize_repo_path(path)
    if p in PROTECTED_FILES:
        return True
    return any(p.startswith(prefix) for prefix in PROTECTED_SUBTREES)


def protected_paths_in_diff(entries: Sequence[DiffEntry]) -> tuple[str, ...]:
    found: set[str] = set()
    for entry in entries:
        for path in entry.changed_paths:
            if is_protected_path(path):
                found.add(normalize_repo_path(path))
    return tuple(sorted(found))


def policy_changed(entries: Sequence[DiffEntry]) -> bool:
    return any(POLICY_PATH in entry.changed_paths for entry in entries)


def gate_integrity(entries: Sequence[DiffEntry]) -> tuple[tuple[str, ...], bool]:
    return protected_paths_in_diff(entries), policy_changed(entries)


# ---------------------------------------------------------------------------
# CODEOWNERS
# ---------------------------------------------------------------------------

_OWNER_RE = re.compile(
    r"^(?:@[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})$"
)


@dataclass(frozen=True, slots=True)
class CodeownersRule:
    index: int
    pattern: str
    owners: tuple[str, ...]
    raw: str
    supported: bool = True
    reason: str = ""


@dataclass(frozen=True, slots=True)
class CodeownersFile:
    path: str
    rules: tuple[CodeownersRule, ...]
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CodeownersCoverage:
    proven: bool
    reasons: tuple[str, ...]
    path: str = ""
    rules: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "proven": self.proven,
            "reasons": list(self.reasons),
            "path": self.path or None,
            "rules": self.rules,
        }


def _validate_pattern(pattern: str) -> tuple[bool, str]:
    if pattern in ("*", "**", "/**"):
        return True, ""
    if not pattern.startswith("/"):
        return False, "codeowners_unanchored_pattern"
    if any(ch in pattern for ch in "![]\\?"):
        return False, "codeowners_unsupported_pattern"
    if "//" in pattern:
        return False, "codeowners_unsupported_pattern"
    body = pattern.strip("/")
    if not body:
        return False, "codeowners_unsupported_pattern"
    if body.endswith("/**"):
        body = body[:-3]
    for part in body.split("/"):
        if part in ("", ".", "..") or ("*" in part and part != "**"):
            return False, "codeowners_unsupported_pattern"
    return True, ""


def parse_codeowners(text: str, *, path: str = "") -> CodeownersFile:
    rules: list[CodeownersRule] = []
    reasons: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if line.startswith("[") or line.startswith("^["):
            reasons.append("codeowners_section_headers_unsupported")
            continue
        tokens = line.split()
        if not tokens:
            continue
        pattern = tokens[0]
        owner_tokens: list[str] = []
        for token in tokens[1:]:
            if token.startswith("#"):
                break
            owner_tokens.append(token)
        supported, reason = _validate_pattern(pattern)
        owners: list[str] = []
        for token in owner_tokens:
            if not _OWNER_RE.match(token):
                supported = False
                reason = reason or "codeowners_invalid_owner"
            else:
                owners.append(token)
        if not owners and supported:
            reasons.append("codeowners_ownerless_rule")
        rules.append(
            CodeownersRule(
                index=len(rules),
                pattern=pattern,
                owners=tuple(owners),
                raw=raw_line,
                supported=supported,
                reason=reason,
            )
        )
    return CodeownersFile(path=path, rules=tuple(rules), reasons=tuple(sorted(set(reasons))))


def _rule_covers(rule: CodeownersRule, target_segments: Sequence[str]) -> bool:
    if not rule.supported:
        return False
    if rule.pattern in ("*", "**", "/**"):
        return True
    pattern = rule.pattern
    if not pattern.startswith("/"):
        return False
    body = pattern.strip("/")
    if body.endswith("/**"):
        body = body[:-3]
    parts = tuple(part for part in body.split("/") if part)
    if not parts:
        return False
    if len(parts) > len(target_segments):
        return False
    return tuple(target_segments[: len(parts)]) == parts


def _rule_intersects(rule: CodeownersRule, target_segments: Sequence[str]) -> bool:
    """Conservatively test whether a later rule can touch a protected path."""
    if not rule.supported:
        return False
    if rule.pattern in ("*", "**", "/**"):
        return True
    if not rule.pattern.startswith("/"):
        return False
    body = rule.pattern.strip("/")
    if body.endswith("/**"):
        body = body[:-3]
    parts = tuple(part for part in body.split("/") if part)
    if not parts:
        return False
    for i, part in enumerate(parts):
        if i >= len(target_segments):
            return True
        if part in ("*", "**"):
            return True
        if part != target_segments[i]:
            return False
    return True


def _check_target(rules: Sequence[CodeownersRule], target: str) -> list[str]:
    segments = _segments(target)
    covering = [rule for rule in rules if _rule_covers(rule, segments)]
    reasons: list[str] = []
    if not covering:
        reasons.append("codeowners_missing_rule")
        return reasons
    last = covering[-1]
    if not last.owners:
        reasons.append("codeowners_ownerless_rule")
    for rule in rules[last.index + 1 :]:
        if not rule.supported:
            continue
        if _rule_intersects(rule, segments) and rule.owners != last.owners:
            reasons.append("codeowners_noninterference_unproven")
            break
    return reasons


def evaluate_codeowners(text: str, *, path: str = "") -> CodeownersCoverage:
    parsed = parse_codeowners(text, path=path)
    reasons: set[str] = set(parsed.reasons)
    for subtree in PROTECTED_SUBTREES:
        reasons.update(_check_target(parsed.rules, subtree))
    for file_path in PROTECTED_FILES:
        reasons.update(_check_target(parsed.rules, file_path))
    return CodeownersCoverage(
        proven=not reasons,
        reasons=tuple(sorted(reasons)),
        path=path,
        rules=len(parsed.rules),
    )


def load_codeowners(git: GitRepo, rev: str) -> tuple[str, str, CodeownersCoverage]:
    for path in CODEOWNERS_LOOKUP:
        raw = git.read_path_at(rev, path)
        if raw is None:
            continue
        if len(raw) > MAX_CODEOWNERS_BYTES:
            return path, "", CodeownersCoverage(
                proven=False,
                reasons=("codeowners_file_too_large",),
                path=path,
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return path, "", CodeownersCoverage(
                proven=False,
                reasons=("codeowners_invalid_utf8",),
                path=path,
            )
        return path, text, evaluate_codeowners(text, path=path)
    return "", "", CodeownersCoverage(
        proven=False,
        reasons=("codeowners_file_missing",),
    )


__all__ = [
    "CODEOWNERS_LOOKUP",
    "CodeownersCoverage",
    "CodeownersFile",
    "CodeownersRule",
    "MAX_CODEOWNERS_BYTES",
    "POLICY_PATH",
    "PROTECTED_FILES",
    "PROTECTED_SUBTREES",
    "evaluate_codeowners",
    "gate_integrity",
    "is_protected_path",
    "load_codeowners",
    "parse_codeowners",
    "policy_changed",
    "protected_paths_in_diff",
]
