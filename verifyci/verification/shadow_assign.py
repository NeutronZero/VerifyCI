"""Shadowed-assignment tripwire (P0 remediation).

A hunk that ADDS an assignment to a name already bound earlier in the
same hunk, with a differing right-hand-side callee set, changes what
the name delivers without removing anything — the exact shape of the
P1 false-PASS (`token = hash_pw(pw)` in context, `+ token =
check_password(pw)` added: the token silently becomes a bool). No
removal means no witness requirement, no call disappearance, no return
pair: every other tripwire stays silent. No premise states either
binding's contract, so the gate cannot judge the shadow: it escalates
to HUMAN_REVIEW (non-blocking, established — the diff text is the
evidence), never FAIL.

Narrow by construction:
- Added lines only. Removed lines never seed candidacy or priors.
- An added line whose LHS also appears among the hunk's REMOVED LHS
  set is a modification (call/return tripwire territory), never a
  shadow — F1b/F2 shapes stay out.
- Prior = a context or added line earlier in the SAME hunk (per-hunk
  scope; cross-hunk rebinding is out of scope, noted not guessed).
  First binding wins; every later differing rebinding is its own site.
- Fire iff prior RHS callee set != added RHS callee set. Identical
  rebinding and same-callee edits (e.g. `y = f(x)` -> `y = f(x*2)`)
  stay silent; constant overwrites (`{...}` vs `{call}`) fire.
- Unsplittable lines (comparisons, no `=`, empty sides) stay silent.
- CODE_CORE hunks only. Evidence uses NEW-side line numbers: the
  shadow lives on the added line.
"""
from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.call_swap import _callees, _is_code_line, _split_lhs
from verifyci.verification.diffmap import iter_hunks
from verifyci.verification.partition import FilePartition, classify_path


def shadowed_assignments(diff: str | None) -> list[str]:
    """`path:new_line` items where an added assignment shadows a prior
    binding with a conflicting RHS callee set. Order-preserving,
    deduplicated by site."""
    out: list[str] = []
    seen: set[str] = set()
    for h in iter_hunks(diff or ""):
        if h.file is None:
            continue
        if classify_path(h.file) != FilePartition.CODE_CORE:
            continue
        removed_lhs: set[str] = set()
        for body in h.lines:
            if body.startswith("-") and not body.startswith("---"):
                if _is_code_line(body[1:]):
                    split = _split_lhs(body[1:])
                    if split is not None:
                        removed_lhs.add(split[0])
        priors: dict[str, set[str]] = {}
        new_ln = h.new_start
        for body in h.lines:
            if body.startswith("\\"):
                continue
            if body.startswith("-"):
                continue
            if body.startswith("+"):
                if _is_code_line(body[1:]):
                    split = _split_lhs(body[1:])
                    if split is not None:
                        lhs, rhs = split
                        if lhs not in removed_lhs:
                            callees = _callees(rhs)
                            if lhs in priors:
                                if priors[lhs] != callees:
                                    key = f"{h.file}:{new_ln}"
                                    if key not in seen:
                                        seen.add(key)
                                        out.append(key)
                            else:
                                priors[lhs] = callees
                new_ln += 1
            else:
                # Context (or unattributable approximate-hunk line):
                # seeds priors, never fires, mirrors sibling handling.
                content = body[1:] if body[:1] in (" ", "+", "-") else body
                if _is_code_line(content):
                    split = _split_lhs(content)
                    if split is not None and split[0] not in priors:
                        priors[split[0]] = _callees(split[1])
                new_ln += 1
    return out


def shadow_assignment_check(diff: str | None) -> CheckResult:
    """Non-blocking tripwire: shadowed assignments route to HUMAN_REVIEW."""
    shadowed = shadowed_assignments(diff)
    if not shadowed:
        return CheckResult(
            check_id="shadowed_assignment",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="no shadowed assignments",
            blocking=False,
        )
    first = shadowed[0]
    rest = f" +{len(shadowed) - 1} more" if len(shadowed) > 1 else ""
    return CheckResult(
        check_id="shadowed_assignment",
        passed=False,
        score=0.0,
        evidence=list(shadowed),
        explanation=f"assignment shadowed at {first}{rest}; "
                    f"rebinding contract unverified",
        blocking=False,
    )
