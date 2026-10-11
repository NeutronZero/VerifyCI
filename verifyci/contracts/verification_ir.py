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
    execution_receipt_id: Optional[str] = None
    execution_verified: bool = False


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
        import warnings

        if not self.valid or not self.signature:
            return False

        alg = (self.algorithm or "hmac-sha256").lower()

        from verifyci.env import get_env as _get_env
        if alg == "hmac-sha256":
            trusted_key = key or _get_env("WAIVER_KEYS")
            if not trusted_key:
                return self._bearer_fallback(allow_bearer, warnings)
            if isinstance(trusted_key, str):
                key_bytes = trusted_key.encode("utf-8")
            else:
                key_bytes = bytes(trusted_key)
            expected = hmac.new(key_bytes, self.canonical_bytes(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(self.signature.lower(), expected.lower())

        if alg == "ed25519":
            trusted_pubkey = key or _get_env("WAIVER_PUBLIC_KEYS")
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
        from verifyci.env import get_env as _get_env
        if allow_bearer is None:
            allow_bearer = _get_env("WAIVER_ALLOW_UNAUTHENTICATED", "") == "1"
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
    - conclusion result is pass
    - on the CODE_CORE path: execution traces non-empty and evidence
      non-empty (grounded entities existed to trace and cite)
    - on the non-code fast paths (documentation / valid configuration /
      test-suite-only / ancillary): traces and evidence are empty BY
      CONSTRUCTION — there are no code entities to trace or cite, so
      verified reflects the partition policy check alone. Such
      certificates never yield a CLI PASS on their own: the
      provenance_check invariant fails on empty evidence, routing the
      end-to-end verdict to HUMAN_REVIEW (exit 2, same as INCONCLUSIVE).
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
    signature: str | None = None
    signing_key_id: str | None = None
    signature_algorithm: str | None = None

    def canonical_bytes(self) -> bytes:
        from verifyci.contracts.canonical import canonical_certificate_bytes
        return canonical_certificate_bytes(self)

    def content_hash(self) -> str:
        from verifyci.contracts.canonical import certificate_hash
        return certificate_hash(self)

    def sign(self, private_key: Any, key_id: str | None = None) -> "Certificate":
        """Signs self.canonical_bytes() using Ed25519 and returns a new frozen Certificate."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if isinstance(private_key, Ed25519PrivateKey):
            priv = private_key
        elif isinstance(private_key, (bytes, bytearray)):
            priv = Ed25519PrivateKey.from_private_bytes(bytes(private_key))
        elif isinstance(private_key, str):
            priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key.strip()))
        else:
            raise TypeError(f"Unsupported private key type: {type(private_key).__name__}")

        if key_id is not None:
            resolved_key_id = key_id
        else:
            pub = priv.public_key()
            if hasattr(pub, "public_bytes_raw"):
                resolved_key_id = pub.public_bytes_raw().hex()
            else:
                from cryptography.hazmat.primitives import serialization
                resolved_key_id = pub.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                ).hex()

        sig_bytes = priv.sign(self.canonical_bytes())
        import dataclasses
        return dataclasses.replace(
            self,
            signature=sig_bytes.hex(),
            signing_key_id=resolved_key_id,
            signature_algorithm="ed25519",
        )

    def verify_signature(self, public_key: Any | None = None) -> bool:
        """Verifies self.signature over self.canonical_bytes().

        If public_key is not provided, tries self.signing_key_id (if 32-byte hex
        public key) or environment variable VERIFYCI_CERTIFICATE_PUBLIC_KEYS.
        Fails closed (returns False) if signature is missing, invalid, or verification fails.
        """
        if not self.signature:
            return False
        if self.signature_algorithm is not None and self.signature_algorithm.lower() != "ed25519":
            return False

        try:
            if isinstance(self.signature, str):
                sig_bytes = bytes.fromhex(self.signature)
            elif isinstance(self.signature, (bytes, bytearray)):
                sig_bytes = bytes(self.signature)
            else:
                return False
        except (ValueError, TypeError):
            return False

        if len(sig_bytes) != 64:
            return False

        canonical = self.canonical_bytes()

        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        def _coerce(k: Any) -> Ed25519PublicKey | None:
            if isinstance(k, Ed25519PublicKey):
                return k
            if isinstance(k, Ed25519PrivateKey):
                return k.public_key()
            if isinstance(k, (bytes, bytearray)):
                if len(k) == 32:
                    try:
                        return Ed25519PublicKey.from_public_bytes(bytes(k))
                    except Exception:
                        return None
                return None
            if isinstance(k, str):
                s = k.strip()
                if len(s) == 64:
                    try:
                        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(s))
                    except Exception:
                        return None
                return None
            return None

        if public_key is not None:
            pub = _coerce(public_key)
            if pub is None:
                return False
            try:
                pub.verify(sig_bytes, canonical)
                return True
            except Exception:
                return False

        # If public_key is not provided, try self.signing_key_id (if 32-byte hex public key)
        if self.signing_key_id:
            pub = _coerce(self.signing_key_id)
            if pub is not None:
                try:
                    pub.verify(sig_bytes, canonical)
                    return True
                except Exception:
                    pass

        # Or environment variable VERIFYCI_CERTIFICATE_PUBLIC_KEYS
        from verifyci.env import get_env as _get_env
        import json
        env_val = _get_env("CERTIFICATE_PUBLIC_KEYS")
        if env_val:
            candidate_keys: list[Any] = []
            stripped = env_val.strip()
            if stripped.startswith(("{", "[")):
                try:
                    parsed = json.loads(stripped)
                    if isinstance(parsed, dict):
                        if self.signing_key_id and self.signing_key_id in parsed:
                            candidate_keys.append(parsed[self.signing_key_id])
                        for v in parsed.values():
                            if isinstance(v, (str, bytes)):
                                candidate_keys.append(v)
                    elif isinstance(parsed, list):
                        candidate_keys.extend(parsed)
                except Exception:
                    pass
            for part in stripped.replace(";", ",").replace("\n", ",").split(","):
                part = part.strip()
                if part and part not in candidate_keys:
                    candidate_keys.append(part)

            for cand in candidate_keys:
                pub = _coerce(cand)
                if pub is not None:
                    try:
                        pub.verify(sig_bytes, canonical)
                        return True
                    except Exception:
                        continue

        return False


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
    status: str = "PASS"
    inconclusive_reason: Optional[str] = None


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
