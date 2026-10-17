"""Contract tests for extension protocols and fail-closed adapter semantics."""

from __future__ import annotations

import pytest

from verifyci.contracts.capabilities import Capability, CapabilityDeclaration, ExecutionStatus
from verifyci.contracts.verdict import FindingReason, Severity, VerificationFinding, VerificationVerdict
from verifyci.core.diff_parser import DiffFileEntry
from verifyci.core.engine import VerificationKernel
from verifyci.core.provenance import verify_removal_provenance
from verifyci.extensions.protocols import (
    DictBaseSourceProvider,
    EquivalenceStatus,
    SymbolicProverProtocol,
    SymbolicResult,
)


class FakeSymbolicProver(SymbolicProverProtocol):
    """Configurable fake solver adapter for protocol contract testing."""

    def __init__(self, target_status: EquivalenceStatus, should_crash: bool = False) -> None:
        self.target_status = target_status
        self.should_crash = should_crash

    def prove_function_diff(
        self,
        file_path: str,
        base_source: str,
        head_source: str,
        timeout_ms: int = 3000,
    ) -> list[SymbolicResult]:
        if self.should_crash:
            raise RuntimeError("Underlying SMT solver segfault / fatal error")

        findings: list[VerificationFinding] = []
        if self.target_status == EquivalenceStatus.PROVEN_DIVERGENT:
            findings.append(
                VerificationFinding(
                    finding_id="fake_diverge",
                    rule_id="VC-SYMBOLIC-DIVERGENCE",
                    severity=Severity.HIGH,
                    verdict=VerificationVerdict.FAIL,
                    reason=FindingReason.SEMANTIC_DIVERGENCE,
                    message="Proved semantic divergence in target function",
                    file_path=file_path,
                )
            )
        elif self.target_status in (EquivalenceStatus.UNKNOWN, EquivalenceStatus.TIMEOUT):
            reason = (
                FindingReason.SMT_TIMEOUT
                if self.target_status == EquivalenceStatus.TIMEOUT
                else FindingReason.CAPABILITY_UNAVAILABLE
            )
            findings.append(
                VerificationFinding(
                    finding_id="fake_undecided",
                    rule_id="VC-SYMBOLIC-UNDECIDED",
                    severity=Severity.HIGH,
                    verdict=VerificationVerdict.INCONCLUSIVE,
                    reason=reason,
                    message=f"SMT solver yielded {self.target_status.value}; failing closed",
                    file_path=file_path,
                )
            )

        return [
            SymbolicResult(
                status=self.target_status,
                target_symbol="calc",
                findings=tuple(findings),
            )
        ]


def test_symbolic_timeout_fails_closed_to_inconclusive() -> None:
    prover = FakeSymbolicProver(EquivalenceStatus.TIMEOUT)
    results = prover.prove_function_diff("src/calc.py", "def f(): return 1", "def f(): return 2")
    assert len(results) == 1
    res = results[0]
    assert res.execution_status == ExecutionStatus.TIMED_OUT
    assert res.findings[0].verdict == VerificationVerdict.INCONCLUSIVE
    assert res.findings[0].reason == FindingReason.SMT_TIMEOUT


def test_symbolic_divergence_fails() -> None:
    prover = FakeSymbolicProver(EquivalenceStatus.PROVEN_DIVERGENT)
    results = prover.prove_function_diff("src/calc.py", "def f(): return 1", "def f(): return 2")
    assert results[0].findings[0].verdict == VerificationVerdict.FAIL
    assert results[0].findings[0].reason == FindingReason.SEMANTIC_DIVERGENCE


def test_symbolic_crash_in_kernel_fails_closed() -> None:
    crashing_prover = FakeSymbolicProver(EquivalenceStatus.ERROR, should_crash=True)

    def extension_checker(entry: DiffFileEntry, base_srcs: Any) -> list[VerificationFinding]:
        results = crashing_prover.prove_function_diff(entry.file_path, entry.base_source, entry.head_source)
        return list(results[0].findings)

    kernel = VerificationKernel(
        extension_checkers=[extension_checker],
        base_sources={"src/calc.py": "def f(): return 1\n"},
    )
    entry = DiffFileEntry.from_sources("src/calc.py", "def f(): return 1\n", "def f(): return 2\n")
    cert = kernel.verify_entries([entry])

    # Crash must fail closed to INCONCLUSIVE, NEVER PASS
    assert cert.verdict == VerificationVerdict.INCONCLUSIVE
    assert any(f.reason == FindingReason.CAPABILITY_UNAVAILABLE for f in cert.payload.findings)


def test_policy_tampering_is_rejected_at_kernel() -> None:
    entry = DiffFileEntry.from_sources(".verifyci.toml", "strict = true\n", "strict = false\n")
    findings = verify_removal_provenance(entry, base_sources={})
    assert len(findings) == 1
    assert findings[0].verdict == VerificationVerdict.FAIL
    assert findings[0].reason == FindingReason.POLICY_VIOLATION


def test_source_provider_protocol_abstraction() -> None:
    provider = DictBaseSourceProvider({"src/app.py": "def run(): pass\n"})
    assert provider.get_file_content("src/app.py") == "def run(): pass\n"
    assert provider.get_file_content("src\\app.py") == "def run(): pass\n"
    assert provider.get_file_content("./src/app.py") == "def run(): pass\n"
    assert provider.get_file_content("missing.py") is None
