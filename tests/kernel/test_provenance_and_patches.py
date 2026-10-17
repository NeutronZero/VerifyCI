"""Tests for removal provenance, adversarial patches, and the verification kernel."""

from __future__ import annotations

from verifyci.contracts.verdict import FindingReason, VerificationVerdict
from verifyci.core.diff_parser import DiffFileEntry, parse_unified_diff
from verifyci.core.engine import VerificationKernel, parseable_source
from verifyci.core.provenance import verify_removal_provenance


def test_honest_removal_against_base() -> None:
    base_src = "def calculate(x):\n    # old comment\n    return x * 2\n"
    head_src = "def calculate(x):\n    return x * 2\n"
    entry = DiffFileEntry.from_sources("src/calc.py", base_src, head_src)

    findings = verify_removal_provenance(entry, {"src/calc.py": base_src})
    assert len(findings) == 0


def test_fabricated_removal_fails_closed() -> None:
    base_src = "def calculate(x):\n    return x * 2\n"
    diff_text = (
        "--- a/src/calc.py\n"
        "+++ b/src/calc.py\n"
        "@@ -1,3 +1,2 @@\n"
        " def calculate(x):\n"
        "-    # this line was never in the base code at all!\n"
        "     return x * 2\n"
    )
    entries = parse_unified_diff(diff_text)
    assert len(entries) == 1
    findings = verify_removal_provenance(entries[0], {"src/calc.py": base_src})

    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert findings[0].reason == FindingReason.FABRICATED_REMOVAL


def test_net_removal_without_base_is_inconclusive() -> None:
    diff_text = (
        "--- a/src/data.py\n"
        "+++ b/src/data.py\n"
        "@@ -1,5 +1,1 @@\n"
        "-def delete_all():\n"
        "-    pass\n"
        "-def reset():\n"
        "-    pass\n"
        "+def keep(): pass\n"
    )
    entries = parse_unified_diff(diff_text)
    # No base source provided
    findings = verify_removal_provenance(entries[0], base_sources={})

    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.INCONCLUSIVE
    assert findings[0].reason == FindingReason.UNGROUNDED_REMOVAL


def test_guard_removal_fails() -> None:
    base_src = "def transfer(amount):\n    assert amount > 0\n    return amount\n"
    head_src = "def transfer(amount):\n    return amount\n"
    entry = DiffFileEntry.from_sources("src/bank.py", base_src, head_src)

    findings = verify_removal_provenance(entry, {"src/bank.py": base_src})
    assert any(f.reason == FindingReason.POLICY_VIOLATION for f in findings)


def test_fragment_repair_empty_body() -> None:
    # Partial hunk ending immediately after def header
    fragment = "def process_request():"
    repaired, err = parseable_source("src/proc.py", fragment)
    assert err is None
    assert "pass" in repaired


def test_end_to_end_kernel_verification() -> None:
    clean_base = "def add(a: int, b: int) -> int:\n    return a + b\n"
    clean_head = "def add(a: int, b: int) -> int:\n    return a + b  # added comment\n"
    entry = DiffFileEntry.from_sources("src/math_ops.py", clean_base, clean_head)

    kernel = VerificationKernel(base_sources={"src/math_ops.py": clean_base})
    cert = kernel.verify_entries([entry])

    assert cert.verdict == VerificationVerdict.PASS
    assert cert.digest is not None
    assert len(cert.digest) == 64
