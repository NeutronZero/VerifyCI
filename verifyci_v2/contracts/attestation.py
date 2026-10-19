from __future__ import annotations

import msgspec
from typing import Iterator, Literal

from verifyci_v2.contracts.canonical import CONTENT_DIGEST_ALGORITHM

SMTStatus = Literal[
    "SAT", "UNSAT", "UNKNOWN", "SOLVER_UNAVAILABLE", "UNVERIFIED_HEURISTIC"
]
SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
VerdictKind = Literal[
    "PASS", "FAIL", "INCONCLUSIVE", "UNGROUNDED",
    "HEURISTIC_EQUIVALENT_CANDIDATE",
]
GateStatus = Literal[
    "COMPLETED", "ABSTAINED_RECONSTRUCTION_FAILED", "SKIPPED_CACHE_HIT",
    "FAILED_CLOSED_ERROR",
]
ProofOutcome = Literal[
    "PROVEN_EQUIVALENT_UNSAT", "PROVEN_DIVERGENT_SAT",
    "INCONCLUSIVE_UNKNOWN", "INCONCLUSIVE_UNSUPPORTED",
    "INCONCLUSIVE_SOLVER_UNAVAILABLE",
]


class GateExecutionReceipt(msgspec.Struct, frozen=True, kw_only=True):
    gate_id: str
    file_path: str
    status: GateStatus
    detail: str = ""


class CounterexampleWitness(msgspec.Struct, frozen=True, kw_only=True):
    """Concrete input assignment extracted from Z3 proving a semantic divergence or defect."""

    checker_id: str
    smt_status: SMTStatus
    input_assignments: dict[str, str | int | float | bool | None]
    base_return_state: str
    head_return_state: str
    proof_time_ms: float


class EquivalenceProofResult(msgspec.Struct, frozen=True, kw_only=True):
    """Discriminated proof outcome; prevents contradictory bool/status tuples."""
    outcome: ProofOutcome
    witness: CounterexampleWitness | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.outcome == "PROVEN_EQUIVALENT_UNSAT" and self.witness is not None:
            raise ValueError("PROVEN_EQUIVALENT_UNSAT cannot carry a counterexample witness")
        if self.outcome == "PROVEN_DIVERGENT_SAT":
            if self.witness is None:
                raise ValueError("PROVEN_DIVERGENT_SAT requires a validated counterexample witness")
            if self.witness.smt_status != "SAT":
                raise ValueError("PROVEN_DIVERGENT_SAT requires a SAT witness")

    @property
    def is_equivalent(self) -> bool:
        return self.outcome == "PROVEN_EQUIVALENT_UNSAT"

    @property
    def smt_status(self) -> SMTStatus:
        return {
            "PROVEN_EQUIVALENT_UNSAT": "UNSAT",
            "PROVEN_DIVERGENT_SAT": "SAT",
            "INCONCLUSIVE_UNKNOWN": "UNKNOWN",
            "INCONCLUSIVE_UNSUPPORTED": "UNKNOWN",
            "INCONCLUSIVE_SOLVER_UNAVAILABLE": "SOLVER_UNAVAILABLE",
        }[self.outcome]

    def __iter__(self) -> Iterator[object]:
        """Temporary compatibility for callers that still unpack the old tuple."""
        yield self.is_equivalent
        yield self.smt_status


class CandidateFix(msgspec.Struct, frozen=True, kw_only=True):
    """Machine-applicable source repair verified in-memory by egglog and Z3."""

    file_path: str
    start_line: int
    end_line: int
    replacement_text: str
    unified_diff: str
    z3_verified_unsat: bool


class VerificationFinding(msgspec.Struct, frozen=True, kw_only=True):
    """Canonical verification finding emitted by Layer 5 symbolic and taint engines."""

    finding_id: str
    rule_id: str
    severity: SeverityLevel
    verdict: VerdictKind
    file_path: str
    start_line: int
    end_line: int
    message: str
    witness: CounterexampleWitness | None = None
    fixes: tuple[CandidateFix, ...] = ()


class InTotoVerificationPredicate(msgspec.Struct, frozen=True, kw_only=True):
    """RFC 8785 canonical in-toto v1.0 predicate payload.

    `content_digest_algorithm` records which digest produced `findings[].finding_id`
    and `ussa_merkle_root`, so a verifier reading this attestation can tell from
    the evidence alone how those identifiers were computed.
    """

    repo_id: str
    base_commit_sha: str
    head_commit_sha: str
    ussa_merkle_root: str
    gittuf_rsl_entry_hash: str
    ai_provider: str
    conformal_profile_hash: str | None
    findings: tuple[VerificationFinding, ...]
    schema_version: str = "verifyci.v2.0"
    content_digest_algorithm: str = CONTENT_DIGEST_ALGORITHM


class DSSESignature(msgspec.Struct, frozen=True, kw_only=True):
    """Dead Simple Signing Envelope (DSSE) cryptographic signature entry."""

    keyid: str
    sig: str


class DSSEEnvelope(msgspec.Struct, frozen=True, kw_only=True):
    """Standard DSSE v1.0 envelope wrapping an RFC 8785 canonical in-toto statement."""

    payloadType: str
    payload: str  # Base64-encoded canonical JCS bytes
    signatures: tuple[DSSESignature, ...]


class RSLReferenceEntry(msgspec.Struct, frozen=True, kw_only=True):
    """Tamper-evident hash-chained Reference State Log (RSL) entry for git ref state."""

    entry_id: str
    parent_entry_id: str | None
    ref_name: str
    target_commit_sha: str
    ussa_merkle_root: str
    dsse_envelope_digest: str
    timestamp_epoch: int
