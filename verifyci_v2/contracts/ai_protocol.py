from __future__ import annotations

import msgspec
from typing import Any, Literal, Protocol, Sequence


GrammarValidationMode = Literal["post_hoc_schema", "token_cfg_mask"]


class BooleanJudgment(msgspec.Struct, frozen=True):
    """Calibrated System 1 boolean judgment (Noul equivalent)."""

    verdict: bool
    probability: float
    rationale_tag: str
    validation_mode: GrammarValidationMode = "post_hoc_schema"


class CategoricalChoice(msgspec.Struct, frozen=True):
    """Calibrated probability distribution over predeclared categorical options."""

    selected: str
    distribution: dict[str, float]
    confidence: float


class OrdinalScore(msgspec.Struct, frozen=True):
    """Calibrated ordinal severity or relevance score."""

    level: str
    normalized_score: float
    confidence: float


class ConformalProfile(msgspec.Struct, frozen=True):
    """Empirical Split Conformal Prediction profile calibrated on held-out corpora."""

    model_id: str
    weights_or_endpoint_hash: str
    alpha: float
    sample_size: int
    q_hat: float
    is_calibrated: bool = True
    tau_safe: float = 1.0
    defect_sample_size: int = 0


class CalibratedDecision(msgspec.Struct, frozen=True):
    """Result of applying the Split Conformal Prediction gate to a System 1 judgment."""

    prediction_set: tuple[str, ...]
    top_choice: str
    raw_probability: float
    abstained: bool
    escalate_to_smt: bool


class ModelAttestationRecord(msgspec.Struct, frozen=True):
    """Cryptographic attestation of the BYO-AI provider, weights, and conformal profile."""

    provider_name: str
    model_id: str
    weights_or_endpoint_hash: str
    prompt_template_hash: str
    conformal_profile_hash: str | None
    validation_mode: Literal["post_hoc_schema", "token_cfg_mask"] = "post_hoc_schema"


class EmbeddingProviderProtocol(Protocol):
    """Protocol for static CPU Model2Vec or user-supplied embedding providers."""

    @property
    def model_id(self) -> str: ...

    @property
    def dimension(self) -> int: ...

    def embed_batch(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]: ...


class DiscriminativeJudgeProtocol(Protocol):
    """Protocol for fast System 1 discriminative classifiers and rerankers."""

    @property
    def provider_name(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    def attestation(
        self, conformal_hash: str | None = None
    ) -> ModelAttestationRecord: ...

    def judge_boolean(
        self, state: dict[str, Any], question: str
    ) -> BooleanJudgment: ...

    def judge_choice(
        self,
        state: dict[str, Any],
        question: str,
        options: Sequence[str],
    ) -> CategoricalChoice: ...

    def judge_score(
        self,
        state: dict[str, Any],
        question: str,
        levels: Sequence[str],
    ) -> OrdinalScore: ...


class GenerativeSynthesizerProtocol(Protocol):
    """Protocol for System 2 CEGIS patch synthesis and intent-to-SMT compilation."""

    @property
    def provider_name(self) -> str: ...

    @property
    def model_id(self) -> str: ...

    def synthesize_patch(
        self,
        *,
        file_path: str,
        original_source: str,
        rule_id: str,
        counterexample_assignments: dict[str, Any],
        attempt: int = 1,
    ) -> str: ...
