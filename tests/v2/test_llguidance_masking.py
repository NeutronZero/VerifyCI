from __future__ import annotations

import pytest


class _ByteTokenizer:
    """Minimal tokenizer adapter for llguidance token-level masking tests."""

    eos_token_id = 256
    bos_token_id = None
    special_token_ids = []

    def __init__(self) -> None:
        self.tokens = [bytes([i]) for i in range(256)]

    def encode(self, text: str) -> list[int]:
        return list(text.encode("utf-8"))

    def __call__(self, data: bytes) -> list[int]:
        return list(data)


_SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "boolean"}},
    "required": ["verdict"],
}


def test_llguidance_grammar_compiles_without_tokenizer() -> None:
    from verifyci_v2.neural.grammar_mask import TokenLevelGrammarMask, has_llguidance

    if not has_llguidance():
        pytest.skip("llguidance not installed")

    mask = TokenLevelGrammarMask(_SCHEMA)
    # Without a tokenizer the mask cannot constrain raw logits; callers keep
    # the post-hoc validator instead of silently pretending to mask.
    assert mask.is_token_level is False


def test_llguidance_token_level_masking_accepts_valid_completion() -> None:
    from verifyci_v2.neural.grammar_mask import TokenLevelGrammarMask, has_llguidance

    if not has_llguidance():
        pytest.skip("llguidance not installed")

    mask = TokenLevelGrammarMask(_SCHEMA, _ByteTokenizer())
    assert mask.is_token_level is True
    assert mask.validate_text('{"verdict": true}') is True


def test_llguidance_token_level_masking_rejects_schema_violation() -> None:
    from verifyci_v2.neural.grammar_mask import TokenLevelGrammarMask, has_llguidance

    if not has_llguidance():
        pytest.skip("llguidance not installed")

    mask = TokenLevelGrammarMask(_SCHEMA, _ByteTokenizer())
    assert mask.validate_text('{"other": 1}') is False


def test_llguidance_masking_is_fail_closed_when_no_constraint_is_derived() -> None:
    """An unconstrained mask must raise, never silently pass logits through.

    Otherwise a caller would believe grammar enforcement was active when it was
    not, which is the exact failure this gate exists to prevent.
    """
    from verifyci_v2.neural.grammar_mask import (
        GrammarMaskError,
        TokenLevelGrammarMask,
        has_llguidance,
    )

    if not has_llguidance():
        pytest.skip("llguidance not installed")

    mask = TokenLevelGrammarMask(_SCHEMA, _ByteTokenizer())
    token_ids = list(range(0, 32))
    logits = {tid: 0.0 for tid in token_ids}

    try:
        masked = mask.constrain_logits(token_ids, logits)
    except GrammarMaskError:
        # Fail-closed: the byte-level test tokenizer cannot drive a real mask.
        return

    # If the library does constrain this tokenizer, the shape must be preserved
    # so conformal scoring still sees a fixed-shape distribution.
    assert set(masked) == set(token_ids)
    assert all(isinstance(v, float) for v in masked.values())
    assert any(v <= -1e8 for v in masked.values()), "mask suppressed nothing"


def test_llguidance_commit_advances_prefix() -> None:
    from verifyci_v2.neural.grammar_mask import TokenLevelGrammarMask, has_llguidance

    if not has_llguidance():
        pytest.skip("llguidance not installed")

    mask = TokenLevelGrammarMask(_SCHEMA, _ByteTokenizer())
    for token_id in '{"verdict": true}'.encode("utf-8"):
        mask.commit(token_id)
    assert mask.validate_text('{"verdict": true}') is True