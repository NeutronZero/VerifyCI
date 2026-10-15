"""Hybrid text retrieval over the RaBitQ index.

`RaBitQHybridIndex` already implements both channels: a BM25 lexical scorer
over document token statistics and a 1-bit quantized vector channel fused by
RRF (`hybrid_rrf_score`), which is the field the index sorts on. What was
missing was an entry point over plain text documents - the index only accepted
U-SSA functions through the ingest path, so v2 had no way to rank arbitrary
corpus text.

This module adds no ranking logic of its own. It exposes the existing hybrid
scorer over a document set and surfaces the per-channel scores so a fusion
decision stays inspectable.
"""

from __future__ import annotations

import msgspec

from verifyci_v2.store.rabitq_index import RaBitQHybridIndex

# Splits identifiers on separators so a query for `handle event 0` reaches a
# document that only ever writes `handle_event_0`.
_NON_WORD = str.maketrans({c: " " for c in ".,;:()[]{}/\\-_\"'`"})


def normalize_for_index(text: str) -> str:
    return text.lower().translate(_NON_WORD)


class RankedDocument(msgspec.Struct, frozen=True, kw_only=True):
    doc_id: str
    hybrid_score: float
    exact_score: float
    lexical_score: float
    rank: int


class TextRetriever(msgspec.Struct, frozen=True, kw_only=True):
    """Hybrid BM25 + vector retrieval over plain text documents."""

    index: RaBitQHybridIndex

    @classmethod
    def build(cls, documents: dict[str, str]) -> "TextRetriever":
        index = RaBitQHybridIndex()
        for doc_id, text in documents.items():
            index.upsert_document(doc_id, doc_id, normalize_for_index(text))
        return cls(index=index)

    def search(self, query: str, top_k: int = 20) -> list[RankedDocument]:
        """Ranks documents, ordered by the index's own hybrid RRF score."""
        stats = self.index.search(normalize_for_index(query), top_k=top_k)
        lexical_terms = normalize_for_index(query).split()
        return [
            RankedDocument(
                doc_id=result.node_uid,
                hybrid_score=result.hybrid_rrf_score,
                exact_score=result.exact_score,
                lexical_score=self.index._bm25_score(  # noqa: SLF001
                    lexical_terms, result.node_uid
                ),
                rank=position,
            )
            for position, result in enumerate(stats.results, start=1)
        ]

    def doc_ids(self) -> list[str]:
        return sorted(self.index._entries)  # noqa: SLF001

    def doc_text(self, doc_id: str) -> str:
        """Original document text, keyed by id, for abstention rules."""
        return self.index._entries[doc_id].qualified_name  # noqa: SLF001