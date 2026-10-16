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
        return str(compiler.compile(__import__("json").dumps(schema), check=True))
    except Exception:
        return None


class TokenLevelGrammarMask:
    """Token-level CFG masking over raw model token logits (spec sec. 3.6B).

    Wraps ``llguidance.LLMatcher`` so a live local model can have its next-token
    logits constrained by the declared JSON schema *before* sampling, instead of
    validating the finished string after the fact.

    Offline default is unchanged: when no tokenizer is supplied the caller keeps
    using :class:`SchemaConstrainedValidator` post-hoc validation.
    """

    def __init__(self, schema: dict, tokenizer: Any = None) -> None:
        if not _HAS_LLGUIDANCE_LIBRARY or _llguidance is None:
            raise GrammarMaskError("llguidance library is not installed")
        grammar = constrained_json_grammar(schema)
        if grammar is None:
            raise GrammarMaskError("schema could not be compiled to a grammar")
        self._schema = schema
        self._grammar = grammar
        self._tokenizer = tokenizer
        self._matcher = None
        if tokenizer is not None:
            # A real model tokenizer is wrapped first: LLMatcher requires the
            # library's own LLTokenizer type, not an arbitrary object.
            wrapped = (
                tokenizer
                if isinstance(tokenizer, _llguidance.LLTokenizer)
                else _llguidance.TokenizerWrapper(tokenizer)
            )
            self._ll_tokenizer = _llguidance.LLTokenizer(
                wrapped, len(wrapped.tokens)
            )
            self._matcher = _llguidance.LLMatcher(self._ll_tokenizer, grammar)

    @property
    def is_token_level(self) -> bool:
        """True when real token-level masking is active (needs a tokenizer)."""
        return self._matcher is not None

    def validate_text(self, text: str) -> bool:
        """Feeds a candidate completion through the grammar and reports validity."""
        if self._matcher is None or self._tokenizer is None:
            raise GrammarMaskError("token-level validation requires a tokenizer")
        self._matcher.reset()
        for token_id in self._tokenizer.encode(text):
            self._matcher.consume_token(token_id)
        return bool(self._matcher.is_accepting())

    def constrain_logits(
        self, token_ids: Sequence[int], logits: dict[int, float]
    ) -> dict[int, float]:
        """Returns logits masked to grammar-allowed tokens at the current prefix.

        Disallowed tokens get a large negative bias instead of being dropped, so
        the caller keeps a fixed-shape distribution for conformal scoring.

        Fail-closed: if the tokenizer/grammar pair yields no usable mask (every
        token still allowed), this raises rather than returning unmasked logits,
        because an unmasked "mask" would silently disable grammar enforcement.
        """
        if self._matcher is None:
            raise GrammarMaskError("logit masking requires a tokenizer")
        bias = self._matcher.compute_logit_bias()
        masked: dict[int, float] = {}
        suppressed = 0
        for token_id in token_ids:
            if self._matcher.is_stopped() or bias[token_id] >= 0.0:
                masked[token_id] = float(logits.get(token_id, 0.0))
            else:
                masked[token_id] = -1e9
                suppressed += 1
        if token_ids and suppressed == 0:
            raise GrammarMaskError(
                "llguidance returned an unconstrained mask for this "
                "tokenizer/grammar pair; refusing to return unmasked logits"
            )
        return masked

    def commit(self, token_id: int) -> None:
        if self._matcher is None:
            raise GrammarMaskError("token-level commit requires a tokenizer")
        self._matcher.consume_token(token_id)
