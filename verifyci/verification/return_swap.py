"""Return-statement swap tripwire (matrix row S3).

A hunk that removes one `return <expr>` and adds a different
`return <expr>` changes what the function hands back — the exact
shape of S3 (`return token` → `return user`), which the gate
previously PASSed. No premise states the returned-value contract
and V1 emits no RETURNS-value analysis, so the gate cannot judge
the swap: it escalates to HUMAN_REVIEW (non-blocking, established —
the diff text is the evidence), never FAIL. A legitimate refactor
that changes a return expression takes the same route; that is the
safe direction.

Scope: CODE_CORE hunks only (partition-gated like every other
diff-text check), exact hunk bodies (approximate `@@@` hunks read
as their stripped lines, same as the deletion tripwire). A line
counts as a return statement only when its stripped content starts
with the `return` keyword followed by end-of-line, whitespace, `(`,
or `;` — comments (`# return x`), strings (`"return x"`), and
identifiers (`returned`, `return_value`) never match. Pure
additions (a second `return` after an early one, e.g. C2/C5/C8)
and pure removals (owned by deletion verification) do not fire:
only a removed/added pair with differing normalized text does.
"""
from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import iter_hunks
from verifyci.verification.partition import FilePartition, classify_path


def _is_return_statement(content: str) -> bool:
    stripped = content.strip()
    if not stripped.startswith("return"):
        return False
    rest = stripped[len("return"):]
    return rest == "" or rest[0] in (" ", "\t", "(", ";")


def _normalize(content: str) -> str:
    return " ".join(content.strip().split())


def swapped_returns(diff: str | None) -> list[str]:
    """`path:old_line` items where a return statement was swapped.

    Per hunk: normalized removed-return texts minus normalized
    added-return texts — any removed text with no identical added
    text is a swap (a pure rename of the whole statement included).
    Order-preserving, deduplicated.
    """
    out: list[str] = []
    seen: set[str] = set()
    for h in iter_hunks(diff):
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
                if _is_return_statement(body[1:]):
                    removed.append((old_ln, _normalize(body[1:])))
                old_ln += 1
            elif body.startswith("+"):
                if _is_return_statement(body[1:]):
                    added.append(_normalize(body[1:]))
            else:
                old_ln += 1
        added_set = set(added)
        for ln, text in removed:
            if text not in added_set:
                key = f"{h.file}:{ln}"
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    return out


def return_statement_check(diff: str | None) -> CheckResult:
    """Non-blocking tripwire: swapped returns route to HUMAN_REVIEW."""
    swapped = swapped_returns(diff)
    if not swapped:
        return CheckResult(
            check_id="return_statement_swap",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="no swapped return statements",
            blocking=False,
        )
    first = swapped[0]
    rest = f" +{len(swapped) - 1} more" if len(swapped) > 1 else ""
    return CheckResult(
        check_id="return_statement_swap",
        passed=False,
        score=0.0,
        evidence=list(swapped),
        explanation=f"return statement swapped at {first}{rest}; "
                    f"returned-value contract unverified",
        blocking=False,
    )
