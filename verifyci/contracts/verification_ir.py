from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class VerificationPlan:
    plan_id: str
    checks: list["VerificationCheck"]
    thresholds: dict[str, float]
    blockers: list[str]
    intent_package_id: str


@dataclass(frozen=True)
class VerificationCheck:
    check_id: str
    type: str
    target: str
    parameters: dict[str, Any]
    blocking: bool


@dataclass(frozen=True)
class ExecutionWitness:
    witness_id: str
    test_file: str
    test_function: Optional[str] = None
    target_entity_id: Optional[str] = None
    target_file: Optional[str] = None
    is_general_regression: bool = False
    association_method: str = "general_regression"


@dataclass(frozen=True)
class SignedIntentWaiver:
    waiver_id: str
    target: str
    signer: str
    signature: str
    reason: str = ""
    valid: bool = True
    algorithm: str = "hmac-sha256"
    key_id: str = ""

    def canonical_bytes(self) -> bytes:
        """Canonical message payload for signing and verification.

        Exact format: UTF-8 encoding of "{waiver_id}:{target}:{signer}:{reason}".
        """
        return f"{self.waiver_id}:{self.target}:{self.signer}:{self.reason}".encode("utf-8")

    def verify_signature(self, key: str | bytes | None = None,
                         allow_bearer: bool | None = None) -> bool:
        """Cryptographically verify the waiver signature.

        Primitives:
        - algorithm='hmac-sha256':
          Symmetric HMAC-SHA256 over canonical_bytes().
          Key: shared secret string from `key` argument or VERIFYCI_WAIVER_KEYS.
          Encoding: lowercase hex string.
        - algorithm='ed25519':
          Asymmetric Ed25519 signature over canonical_bytes().
          Key: Ed25519 public key bytes or hex string from `key` or VERIFYCI_WAIVER_PUBLIC_KEYS.
          Encoding: lowercase hex string or raw bytes.

        Deny by default: when no key/secret is configured AND no explicit
        `key` is passed, verification FAILS — an unverifiable waiver
        suppresses nothing. The old unauthenticated bearer-token fallback
        (any non-empty signature accepted) is available ONLY via explicit
        opt-in: `allow_bearer=True` or VERIFYCI_WAIVER_ALLOW_UNAUTHENTICATED=1,
        which emits a RuntimeWarning every time it accepts. Bearer mode
        exists for air-gapped/manual workflows, never as a silent default:
        anyone able to write waivers.yaml could otherwise suppress
        guard-removal FAILs with a made-up signature.
        """
        import hashlib
        import hmac
        import os
        import warnings

        if not self.valid or not self.signature:
            return False

        alg = (self.algorithm or "hmac-sha256").lower()

        if alg == "hmac-sha256":
            trusted_key = key or os.getenv("VERIFYCI_WAIVER_KEYS")
            if not trusted_key:
                return self._bearer_fallback(allow_bearer, warnings)
            if isinstance(trusted_key, str):
                key_bytes = trusted_key.encode("utf-8")
            else:
                key_bytes = bytes(trusted_key)
            expected = hmac.new(key_bytes, self.canonical_bytes(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(self.signature.lower(), expected.lower())

        if alg == "ed25519":
            trusted_pubkey = key or os.getenv("VERIFYCI_WAIVER_PUBLIC_KEYS")
            if not trusted_pubkey:
                return self._bearer_fallback(allow_bearer, warnings)
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                if isinstance(trusted_pubkey, str):
                    pub_bytes = bytes.fromhex(trusted_pubkey)
                else:
                    pub_bytes = bytes(trusted_pubkey)
                pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
                sig_bytes = bytes.fromhex(self.signature) if isinstance(self.signature, str) else self.signature
                pub.verify(sig_bytes, self.canonical_bytes())
                return True
            except Exception:
                return False

        return False

    def _bearer_fallback(self, allow_bearer: bool | None, warnings) -> bool:
        """Explicit-opt-in-only unauthenticated acceptance. Deny otherwise."""
        import os
        if allow_bearer is None:
            allow_bearer = os.getenv("VERIFYCI_WAIVER_ALLOW_UNAUTHENTICATED", "") == "1"
        if not allow_bearer:
            return False
        warnings.warn(
            f"waiver {self.waiver_id!r} accepted WITHOUT cryptographic "
            f"verification (bearer fallback opted in) — anyone able to write "
            f"waivers.yaml can suppress guard-removal failures",
            RuntimeWarning, stacklevel=4,
        )
        return True


@dataclass(frozen=True)
class Certificate:
    '''
    certificate_verified is True if and only if:
    - all deterministic checks passed and checked_by non-empty
    - execution traces non-empty
    - evidence non-empty
    - conclusion result is pass
    '''
    certificate_id: str
    premises: list["Premise"]
    evidence: list["FileEvidence"]
    execution_traces: list["ExecutionTrace"]
    conclusion: "Conclusion"
    confidence: float
    generated_by: str
    checked_by: list[str]
    verification_method: str
    certificate_verified: bool
    timestamp: float
    witnesses: tuple[ExecutionWitness, ...] = ()
    waivers: tuple[SignedIntentWaiver, ...] = ()


@dataclass(frozen=True)
class Premise:
    premise_id: str
    statement: str
    source: str


@dataclass(frozen=True)
class FileEvidence:
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    source_hash: str


@dataclass(frozen=True)
class ExecutionTrace:
    trace_id: str
    path: list[str]
    conditions: list[str]
    """Control-flow guards under which the path is taken. Reserved for the
    V1.1 CFG/DFG; V1 AST-derived CPG has no guard edges, so producers leave
    this empty rather than filling it with traversal metadata."""


@dataclass(frozen=True)
class Conclusion:
    result: str
    reasoning: str


@dataclass(frozen=True)
class BlastRadiusResult:
    affected_callers: list[str]
    affected_callees: list[str]
    test_coverage_gap: list[str]
    risk_score: float
    dependency_impact: list[str]
    vulnerability_impact: list[str]


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    passed: bool
    score: float
    evidence: list[str]
    explanation: str
    blocking: bool = True
    certificate: Optional[Certificate] = None
    deterministic: bool = True  # False for LLM-opinion checks (policy ignores them)
    established: bool = True  # False when the check ran against nothing
    # (e.g. zero relevant edges): inability, not rejection. Policy routes
    # established blocking failures to FAIL and unestablished ones to
    # INCONCLUSIVE — a pass-on-zero-edges is a different verdict from a
    # pass-on-500-edges, recorded here rather than in prose.


@dataclass(frozen=True)
class VerificationReport:
    report_id: str
    task_id: str
    policy_id: str
    checks: list[CheckResult]
    blast_radius: BlastRadiusResult
    timestamp: float


@dataclass(frozen=True)
class VerificationPolicy:
    policy_id: str
    on_failure: str
    on_inconclusive: str
    on_human_review: str
    require_deterministic_checker: bool


@dataclass(frozen=True)
class VerificationDecision:
    decision_id: str
    report_id: str
    status: str
    policy_id: str
    rationale: str
    timestamp: float


@dataclass(frozen=True)
class InvariantMetrics:
    check_coverage: float
    detection_recall: Optional[float] = None
    detection_precision: Optional[float] = None
    """Recall/precision are None when unmeasured (no labeled ground truth).
    None renders as null in JSON — deliberately distinct from 0.0, which
    would read as "measured and terrible". """


@dataclass(frozen=True)
class Invariant:
    invariant_id: str
    rule: str
    compiled_query: str
    blocking: bool
    target_scope: str = "global_strict"
    test_allowlist_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class IntentPackage:
    intent_package_id: str
    specs: list[dict[str, Any]]
    invariants: list[Invariant]
    nfrs: list[dict[str, Any]]
    verification_plan_id: str
