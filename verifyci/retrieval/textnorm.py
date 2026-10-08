"""Identifier-aware tokenization shared by lexical retrieval stages.

Code text is snake_case, camelCase, dotted paths, and file paths separated
by slashes. Plain whitespace splitting never matches "beam search" against
"beam_search_paths" — every lexical stage (BM25, overlap rerank) must use
this, or candidate generation and ranking disagree about what a token is.
"""
import re
import unicodedata

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ACRONYM = re.compile(r"([A-Z]+)([A-Z][a-z])")
# P4: unicode word characters (\\w is Unicode-aware), underscores
# pre-split to preserve the historical ASCII behavior where `_` separates
# ("beam_search" -> ["beam", "search"]). NFKC folds width/case variants
# (full-width, compatibility) before lowering so café/CJK identifiers
# tokenize instead of vanishing through the old [^a-z0-9]+ filter.
_SPLIT = re.compile(r"[^\w]+", re.UNICODE)


def tokenize(text: str) -> list[str]:
    if not text:
        return []
    normalized = unicodedata.normalize("NFKC", text).replace("_", " ")
    spaced = _ACRONYM.sub(r"\1 \2", normalized)  # HTTPResponse -> HTTP Response
    spaced = _CAMEL.sub(" ", spaced)  # beamSearch -> beam Search
    return [t for t in _SPLIT.split(spaced.lower()) if t]
