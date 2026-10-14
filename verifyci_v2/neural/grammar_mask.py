from __future__ import annotations

import json
import math
from typing import Any, Sequence

from verifyci_v2.contracts.ai_protocol import (
    BooleanJudgment,
    CategoricalChoice,
    OrdinalScore,
)


class GrammarMaskError(ValueError):
    """Raised when a model output violates the predeclared llguidance CFG/JSON schema."""


class LLGuidanceSchemaMask:
    """
    Enforces schema-locked structured decoding and converts raw token logprobs or logits
    into calibrated probability distributions with zero syntax retry loops.
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
    def parse_constrained_boolean(raw_json_or_dict: str | dict[str, Any]) -> BooleanJudgment:
        data = (
            json.loads(raw_json_or_dict)
            if isinstance(raw_json_or_dict, str)
            else raw_json_or_dict
        )
        if not isinstance(data, dict) or "verdict" not in data or "probability" not in data:
            raise GrammarMaskError("Invalid BooleanJudgment schema")
        prob = float(data["probability"])
        if not (0.0 <= prob <= 1.0):
            raise GrammarMaskError(f"Probability {prob} outside [0.0, 1.0]")
        return BooleanJudgment(
            verdict=bool(data["verdict"]),
            probability=round(prob, 6),
            rationale_tag=str(data.get("rationale_tag", "constrained_cfg")),
        )

    @staticmethod
    def build_constrained_choice(
        options: Sequence[str],
        option_logits: dict[str, float],
    ) -> CategoricalChoice:
        if not options:
            raise GrammarMaskError("CategoricalChoice requires at least one option")
        filtered_logits = {opt: float(option_logits.get(opt, -10.0)) for opt in options}
        dist = LLGuidanceSchemaMask.softmax_from_logits(filtered_logits)
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
        choice = LLGuidanceSchemaMask.build_constrained_choice(levels, level_logits)
        idx = list(levels).index(choice.selected)
        norm_score = idx / max(1, len(levels) - 1)
        return OrdinalScore(
            level=choice.selected,
            normalized_score=round(norm_score, 6),
            confidence=choice.confidence,
        )