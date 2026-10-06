"""Guard-condition inversion tripwire (Contract 4 & CAP-005).

Detects when an authorization or security guard condition is inverted in-place
(such as `if not user.is_authenticated:` -> `if user.is_authenticated:`),
permitting unauthorized access bypass while retaining the error-raising body.
Escalates to HUMAN_REVIEW (non-blocking, established), never silent PASS.
"""
from __future__ import annotations

import re

from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import iter_hunks
from verifyci.verification.partition import FilePartition, classify_path

_GUARD_KW_RE = re.compile(
    r"(?:auth\w*|permit\w*|permission\w*|allow\w*|valid\w*|check_\w*|verify_\w*|login\w*|admin\w*|token\w*|guard\w*)",
    re.IGNORECASE,
)


def _normalize_cond(line: str) -> str:
    s = line.strip()
    if s.startswith("if "):
        s = s[3:]
    if s.endswith(":"):
        s = s[:-1]
    return s.strip()


def _is_inverted(c_rem: str, c_add: str) -> bool:
    if c_rem.startswith("not ") and c_rem[4:].strip() == c_add:
        return True
    if c_add.startswith("not ") and c_add[4:].strip() == c_rem:
        return True
    if c_rem.startswith("!") and c_rem[1:].strip() == c_add:
        return True
    if c_add.startswith("!") and c_add[1:].strip() == c_rem:
        return True
    if ("True" in c_rem and "False" in c_add) or ("False" in c_rem and "True" in c_add):
        base_rem = c_rem.replace("True", "").replace("False", "").strip()
        base_add = c_add.replace("True", "").replace("False", "").strip()
        if base_rem == base_add:
            return True
    return False


def inverted_guards(diff: str | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for h in iter_hunks(diff or ""):
        if h.file is None or classify_path(h.file) != FilePartition.CODE_CORE:
            continue
        rem_guards: list[tuple[int, str]] = []
        add_guards: list[str] = []
        old_ln = h.old_start
        for body in h.lines:
            if body.startswith("-") and not body.startswith("---"):
                stripped = body[1:].strip()
                if stripped.startswith("if ") and _GUARD_KW_RE.search(stripped):
                    rem_guards.append((old_ln, _normalize_cond(stripped)))
                old_ln += 1
            elif body.startswith("+") and not body.startswith("+++"):
                stripped = body[1:].strip()
                if stripped.startswith("if ") and _GUARD_KW_RE.search(stripped):
                    add_guards.append(_normalize_cond(stripped))
            elif not body.startswith("\\"):
                old_ln += 1

        for ln, rg in rem_guards:
            for ag in add_guards:
                if _is_inverted(rg, ag):
                    loc = f"{h.file}:{ln}"
                    if loc not in seen:
                        seen.add(loc)
                        out.append(loc)

    return out


def guard_condition_check(diff: str | None) -> CheckResult:
    inversions = inverted_guards(diff)
    if not inversions:
        return CheckResult(
            check_id="guard_condition_inversion",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="no inverted guard conditions",
            blocking=False,
        )
    first = inversions[0]
    rest = f" +{len(inversions) - 1} more" if len(inversions) > 1 else ""
    return CheckResult(
        check_id="guard_condition_inversion",
        passed=False,
        score=0.0,
        evidence=list(inversions),
        explanation=f"guard condition inverted at {first}{rest}; authorization contract unverified",
        blocking=False,
    )
