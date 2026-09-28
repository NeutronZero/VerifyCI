"""Identifier-aware tokenization shared by lexical retrieval stages.

Code text is snake_case, camelCase, dotted paths, and file paths separated
by slashes. Plain whitespace splitting never matches "beam search" against
"beam_search_paths" — every lexical stage (BM25, overlap rerank) must use
this, or candidate generation and ranking disagree about what a token is.
"""
import re

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^a-z0-9]+")


def tokenize(text: str) -> list[str]:
    if not text:
        return []
    spaced = _CAMEL.sub(" ", text)
    return [t for t in _SPLIT.split(spaced.lower()) if t]
