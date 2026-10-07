# Extending VerifyCI: Adding Verification Checkers

This guide explains how to write, register, test, and benchmark a new deterministic verification checker in VerifyCI.

---

## 1. Checker Interface & Result Model

All verification checks in VerifyCI yield an immutable `CheckResult` contract object defined in `verifyci/contracts/verification_ir.py`:

```python
from dataclasses import dataclass
from typing import Optional
from verifyci.contracts.verification_ir import Certificate

@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    score: float
    evidence: list[str]
    explanation: str
    blocking: bool = True
    certificate: Optional[Certificate] = None
    deterministic: bool = True
    established: bool = True
```

### Key Semantics:
- **`check_id`**: A unique string identifying the check (e.g., `"no_unsafe_deserialization"`).
- **`passed`**: `True` if no violation was found; `False` if a violation occurred.
- **`blocking`**: If `True`, a failure causes `PolicyEvaluator` to reject the diff with a `FAIL` verdict (exit code 1). If `False`, the failure is routed to `HUMAN_REVIEW` (exit code 2).
- **`established`**: **Critical safety invariant**. Indicates whether the check had relevant code entities/edges to evaluate. If `established=False` (e.g. check evaluated 0 relevant edges or ungroundable content), the policy routes to `INCONCLUSIVE` rather than counting as a false pass or unfair rejection.
- **`deterministic`**: Must be `True` for all algorithmic and rule-based checks. Set `False` for LLM opinions (which VerifyCI policy strictly ignores).
- **`evidence`**: Formatted location strings citing the exact files and lines (e.g., `["src/parser.py:42:pickle.loads"]`).

---

## 2. Implementing a Checker

Create a dedicated module in `verifyci/verification/` (e.g., `verifyci/verification/deserialization.py`):

```python
import re
from verifyci.contracts.verification_ir import CheckResult
from verifyci.verification.diffmap import iter_added_lines_with_lineno

_FORBIDDEN_CALLS = re.compile(r"\b(pickle\.loads|yaml\.unsafe_load|marshal\.loads)\b")

def unsafe_deserialization_check(diff: str) -> CheckResult:
    """Detect unsafe deserialization functions introduced in added diff lines."""
    if not diff or not diff.strip():
        return CheckResult(
            check_id="unsafe_deserialization",
            passed=True,
            score=1.0,
            evidence=[],
            explanation="empty diff, nothing to evaluate",
            blocking=True,
            established=True,
        )

    violations = []
    for file_path, lineno, line_content in iter_added_lines_with_lineno(diff):
        match = _FORBIDDEN_CALLS.search(line_content)
        if match:
            loc = f"{file_path}:{lineno or '?'}:{match.group(1)}"
            violations.append(loc)

    if violations:
        return CheckResult(
            check_id="unsafe_deserialization",
            passed=False,
            score=0.0,
            evidence=violations,
            explanation=f"unsafe deserialization detected in {violations[0]}",
            blocking=True,
            established=True,
        )

    return CheckResult(
        check_id="unsafe_deserialization",
        passed=True,
        score=1.0,
        evidence=[],
        explanation="no unsafe deserialization calls introduced",
        blocking=True,
        established=True,
    )
```

---

## 3. Registering the Checker

### Option A: Diff Verification Pipeline
Add the check to `run_verify` in `verifyci/interface/commands/verify.py`:

```python
from verifyci.verification.deserialization import unsafe_deserialization_check

# In run_verify():
checks.append(unsafe_deserialization_check(diff))
```

### Option B: Invariant Query Dispatcher
If the checker should be configurable via `.verifyci/invariants.yaml`, register its query prefix in `verifyci/verification/intent_align.py` (`_check_invariant`):

```python
if query.startswith("forbid_deserialization:"):
    # Dispatch query
```

---

## 4. PolicyEvaluator Integration

`PolicyEvaluator` (`verifyci/verification/policy.py`) evaluates the compiled `VerificationReport`:
1. If any blocking check fails and is `established=True` -> Verdict: `FAIL` (exit 1).
2. If any blocking check is `established=False` (inability) -> Verdict: `INCONCLUSIVE` (exit 2).
3. If non-blocking checks fail -> Verdict: `HUMAN_REVIEW` (exit 2).
4. If all checks pass and are established -> Verdict: `PASS` (exit 0).

Never bypass or weaken the `PolicyEvaluator` invariants.

---

## 5. Adding Automated Tests

Create tests in `tests/verification/` following the Arrange-Act-Assert (AAA) pattern:

```python
from verifyci.verification.deserialization import unsafe_deserialization_check

def test_unsafe_deserialization_detects_pickle():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+data = pickle.loads(raw_input)\n"
    )
    result = unsafe_deserialization_check(diff)
    assert result.passed is False
    assert result.blocking is True
    assert "pickle.loads" in result.evidence[0]

def test_unsafe_deserialization_passes_clean_diff():
    diff = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+data = json.loads(raw_input)\n"
    )
    result = unsafe_deserialization_check(diff)
    assert result.passed is True
```

---

## 6. Frozen Benchmark Protection Rules

VerifyCI relies on frozen empirical benchmarks (`benchmarks/`). When adding or updating checkers:

- **Do NOT alter frozen corpora**: Never edit files in `benchmarks/patch_corpus/`, `benchmarks/blast_corpus/`, or `benchmarks/temporal_corpus/`.
- **Do NOT retune thresholds retroactively**: Historical benchmarks record baseline evidence and must remain immutable.
- **New evaluations get new directories**: If you are benchmarking a new capability, create a new subfolder (e.g. `benchmarks/patch_real/cap009/`).
- **Clean-room oracles**: Benchmark evaluation harnesses must derive expected labels independently of the production checker code under test.
