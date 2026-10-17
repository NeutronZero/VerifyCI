from __future__ import annotations

from verifyci_v2.contracts.ai_protocol import (
    CalibratedDecision,
    CategoricalChoice,
    ConformalProfile,
    DiscriminativeJudgeProtocol,
    GrammarValidationMode,
    ModelAttestationRecord,
    OrdinalScore,
)
from verifyci_v2.contracts.attestation import (
    CandidateFix,
    CounterexampleWitness,
    InTotoVerificationPredicate,
    VerificationFinding,
)
from verifyci_v2.contracts.canonical import (
    CONTENT_DIGEST_ALGORITHM,
    FINGERPRINT_ALGORITHM,
    CanonicalSerializationError,
    canonical_digest,
    canonical_jcs_bytes,
    canonical_jcs_str,
    content_digest_bytes,
    content_digest_hex,
    fingerprint_hex,
)
from verifyci_v2.contracts.conformal import (
    calibrate_judge_on_dataset,
    compute_conformal_quantile,
    conformal_profile_digest,
    evaluate_with_conformal_gate,
)
from verifyci_v2.contracts.redaction import (
    RedactionResult,
    redact_in_place_mapping,
    redact_secrets,
)
from verifyci_v2.contracts.ssa_ir import (
    CPGEdge,
    CutoffEvaluation,
    CutoffStatus,
    FunctionUSSA,
    USSABasicBlock,
    USSAFunction,
    USSAInstruction,
)

__all__ = [
    "CONTENT_DIGEST_ALGORITHM",
    "CPGEdge",
    "FINGERPRINT_ALGORITHM",
    "CalibratedDecision",
    "CandidateFix",
    "CanonicalSerializationError",
    "CategoricalChoice",
    "ConformalProfile",
    "CounterexampleWitness",
    "CutoffEvaluation",
    "CutoffStatus",
    "DiscriminativeJudgeProtocol",
    "FunctionUSSA",
    "GrammarValidationMode",
    "InTotoVerificationPredicate",
    "ModelAttestationRecord",
    "OrdinalScore",
    "RedactionResult",
    "USSABasicBlock",
    "USSAFunction",
    "USSAInstruction",
    "VerificationFinding",
    "content_digest_bytes",
    "content_digest_hex",
    "calibrate_judge_on_dataset",
    "canonical_digest",
    "canonical_jcs_bytes",
    "canonical_jcs_str",
    "compute_conformal_quantile",
    "conformal_profile_digest",
    "evaluate_with_conformal_gate",
    "redact_in_place_mapping",
    "redact_secrets",
    "fingerprint_hex",
]
