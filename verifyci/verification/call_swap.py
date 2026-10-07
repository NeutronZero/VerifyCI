"""Call-target swap tripwire (matrix row S2).

A hunk that drops a called function from a statement while keeping
the statement's left-hand side (`token = hash_pw(pw)` →
`token = check_password(pw)`) changes the call contract — the exact
shape of S2, the last remaining false PASS. No premise states either
callee's return contract, so the gate cannot judge the swap: it
escalates to HUMAN_REVIEW (non-blocking, established — the diff
text is the evidence), never FAIL. A legitimate helper rename takes
the same route; that is the safe direction.

Narrow by construction:
- Same-LHS pairing: the removed and added lines share identical
  normalized text before the first `=` (comparison operators
  `==`/`<=`/`>=`/`!=` and arrows `=>`/`->` never split). A swap
  that also renames the assignee is out of scope (noted, not
  guessed).
- Disappearance, not addition: only a removed callee with no
  identical added callee fires (`f(a)` → `f(a) + g(b)` keeps `f`
  and stays silent; argument-only changes keep every callee and
  stay silent).
- CODE_CORE hunks only (partition-gated like every other
  diff-text check). Approximate (`@@@`) hunks read as their stripped
  lines, same as the return tripwire. Comment/string-looking lines
  (`#`, `//`, `*`, quotes) and lines
  without an assignment split. Residual: trailing comments and
  multi-line block comments can misread — fail-closed review
  absorbs it (HUMAN_REVIEW, never FAIL).
"""
import re

from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import iter_hunks
from verifyci.verification.partition import FilePartition, classify_path

_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\s*\(")
_SPLIT_RE = re.compile(r"==|<=|>=|!=|=>|->")
_COMMENT_STARTS = ("#", "//", "*", '"""', "'''", '"', "'")


def _is_code_line(content: str) -> bool:
    return not content.strip().startswith(_COMMENT_STARTS)


def _split_lhs(content: str) -> tuple[str, str] | None:
    """(normalized lhs, rhs) on the first plain `=`, else None."""
    cleaned = _SPLIT_RE.sub("\x00", content)
    head, sep, tail = cleaned.partition("=")
    if not sep or not head.strip() or not tail.strip():
        return None
    lhs = " ".join(head.replace("\x00", "").strip().split())
    return (lhs, tail) if lhs else None


def _callees(content: str) -> set[str]:
    return set(_CALL_RE.findall(content))


def swapped_call_targets(diff: str | None) -> list[str]:
    """`path:old_line` items where a statement lost a callee.

    Per hunk: removed lines (with old-side numbers) and added lines
    are paired by identical normalized LHS; a pair fires when a
    removed callee has no identical added callee. Order-preserving,
    deduplicated.
    """
    out: list[str] = []
    seen: set[str] = set()
    for h in iter_hunks(diff or ""):
        if h.file is None:
            continue
        if classify_path(h.file) != FilePartition.CODE_CORE:
            continue
        removed: list[tuple[int, str]] = []
        added: list[str] = []
        old_ln = h.old_start
        for body in h.lines:
            if body.startswith("\\"):
                continue
            if body.startswith("-"):
                if _is_code_line(body[1:]):
                    removed.append((old_ln, body[1:]))
                old_ln += 1
            elif body.startswith("+"):
                if _is_code_line(body[1:]):
                    added.append(body[1:])
            else:
                old_ln += 1
        added_by_lhs: dict[str, set[str]] = {}
        for line in added:
            split = _split_lhs(line)
            if split is None:
                continue
            added_by_lhs.setdefault(split[0], set()).update(_callees(split[1]))
        for ln, line in removed:
            split = _split_lhs(line)
            if split is None:
                continue
            lhs, rhs = split
            if lhs not in added_by_lhs:
                continue
            if _callees(rhs) - added_by_lhs[lhs]:
                key = f"{h.file}:{ln}"
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    return out


def call_target_check(diff: str | None) -> CheckResult:
    """Non-blocking tripwire: swapped call targets route to HUMAN_REVIEW."""
    swapped = swapped_call_targets(diff)
    if not swapped:
        return CheckResult(
            check_id="call_target_swap",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="no swapped call targets",
            blocking=False,
        )
    first = swapped[0]
    rest = f" +{len(swapped) - 1} more" if len(swapped) > 1 else ""
    return CheckResult(
        check_id="call_target_swap",
        passed=False,
        score=0.0,
        evidence=list(swapped),
        explanation=f"call target swapped at {first}{rest}; "
                    f"callee contract unverified",
        blocking=False,
    )
