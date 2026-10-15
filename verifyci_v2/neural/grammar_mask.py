from __future__ import annotations

import json
import math
from typing import Any, Sequence
import warnings

from verifyci_v2.contracts.ai_protocol import (
    BooleanJudgment,
    CategoricalChoice,
    OrdinalScore,
)

try:
    import llguidance as _llguidance  # type: ignore[import-not-found]
    _HAS_LLGUIDANCE_LIBRARY = True
except Exception:  # pragma: no cover
    _llguidance = None
    _HAS_LLGUIDANCE_LIBRARY = False


class GrammarMaskError(ValueError):
    """Raised when a model output violates the predeclared JSON schema."""


class SchemaConstrainedValidator:
    """
    Enforces post-hoc schema-locked structured validation and converts raw token logprobs or logits
    into calibrated probability distributions. Note: this runs post-hoc validation, not token-level CFG masking.
    """

    @staticmethod
    def softmax_from_logits(logits: dict[str, float]) -> dict[str, float]:
        if not logits:
            raise GrammarMaskError("Cannot normalize empty logit map")
        max_l = max(logits.values())
        exps = {k: math.exp(v - max_l) for k, v in logits.items()}
        total = sum(exps.values())
        return {k: round(v / total, 6) for k, v in exps.items()}

    @staticmethod
    def parse_constrained_boolean(
        raw_json_or_dict: str | dict[str, Any],
    ) -> BooleanJudgment:
        data = (
            json.loads(raw_json_or_dict)
            if isinstance(raw_json_or_dict, str)
            else raw_json_or_dict
        )
        if (
            not isinstance(data, dict)
            or "verdict" not in data
            or "probability" not in data
        ):
            raise GrammarMaskError("Invalid BooleanJudgment schema")
        prob = float(data["probability"])
        if not (0.0 <= prob <= 1.0):
            raise GrammarMaskError(f"Probability {prob} outside [0.0, 1.0]")
        return BooleanJudgment(
            verdict=bool(data["verdict"]),
            probability=round(prob, 6),
            rationale_tag=str(data.get("rationale_tag", "schema_validated")),
            validation_mode="post_hoc_schema",
        )

    @staticmethod
    def build_constrained_choice(
        options: Sequence[str],
        option_logits: dict[str, float],
    ) -> CategoricalChoice:
        if not options:
            raise GrammarMaskError("CategoricalChoice requires at least one option")
        filtered_logits = {opt: float(option_logits.get(opt, -10.0)) for opt in options}
        dist = SchemaConstrainedValidator.softmax_from_logits(filtered_logits)
        best_opt = max(dist.items(), key=lambda kv: kv[1])[0]
        return CategoricalChoice(
            selected=best_opt,
            distribution=dist,
            confidence=dist[best_opt],
        )

    @staticmethod
    def build_constrained_score(
        levels: Sequence[str],
        level_logits: dict[str, float],
    ) -> OrdinalScore:
        if not levels:
            raise GrammarMaskError("OrdinalScore requires at least one level")
        choice = SchemaConstrainedValidator.build_constrained_choice(
            levels, level_logits
        )
        idx = list(levels).index(choice.selected)
        norm_score = idx / max(1, len(levels) - 1)
        return OrdinalScore(
            level=choice.selected,
            normalized_score=round(norm_score, 6),
            confidence=choice.confidence,
        )


class LLGuidanceSchemaMask(SchemaConstrainedValidator):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "LLGuidanceSchemaMask is deprecated, use SchemaConstrainedValidator instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)

def has_llguidance() -> bool:
    return bool(_HAS_LLGUIDANCE_LIBRARY)


def constrained_json_grammar(schema: dict) -> str | None:
    if not _HAS_LLGUIDANCE_LIBRARY or _llguidance is None:
        return None
    try:
        compiler = _llguidance.JsonCompiler()
        return str(compiler.compile(__import__('json').dumps(schema), check=True))
    except Exception:
        return None
