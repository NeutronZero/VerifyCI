from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SMTStatus = Literal["SAT", "UNSAT", "UNKNOWN"]
SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
VerdictKind = Literal["PASS", "WARN", "FAIL", "PROVEN_EQUIVALENT", "UNGROUNDED"]


@dataclass(frozen=True, slots=True)
class CounterexampleWitness:
    """Concrete input assignment extracted from Z3 proving a semantic divergence or defect."""

    checker_id: str
    smt_status: SMTStatus
    input_assignments: dict[str, str | int | float | bool | None]
    base_return_state: str
    head_return_state: str
    proof_time_ms: float


@dataclass(frozen=True, slots=True)
class CandidateFix:
    """Machine-applicable source repair verified in-memory by egglog and Z3."""

    file_path: str
    start_line: int
    end_line: int
    replacement_text: str
    unified_diff: str
    z3_verified_unsat: bool


@dataclass(frozen=True, slots=True)
class VerificationFinding:
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


@dataclass(frozen=True, slots=True)
class InTotoVerificationPredicate:
    """RFC 8785 canonical in-toto v1.0 predicate payload."""

    repo_id: str
    base_commit_sha: str
    head_commit_sha: str
    ussa_merkle_root: str
    gittuf_rsl_entry_hash: str
    ai_provider: str
    conformal_profile_hash: str | None
    findings: tuple[VerificationFinding, ...]
    schema_version: str = "verifyci.v2.0"


@dataclass(frozen=True, slots=True)
class DSSESignature:
    """Dead Simple Signing Envelope (DSSE) cryptographic signature entry."""

    keyid: str
    sig: str


@dataclass(frozen=True, slots=True)
class DSSEEnvelope:
    """Standard DSSE v1.0 envelope wrapping an RFC 8785 canonical in-toto statement."""

    payloadType: str
    payload: str  # Base64-encoded canonical JCS bytes
    signatures: tuple[DSSESignature, ...]


@dataclass(frozen=True, slots=True)
class RSLReferenceEntry:
    """Tamper-evident hash-chained Reference State Log (RSL) entry for git ref state."""

    entry_id: str
    parent_entry_id: str | None
    ref_name: str
    target_commit_sha: str
    ussa_merkle_root: str
    dsse_envelope_digest: str
    timestamp_epoch: int