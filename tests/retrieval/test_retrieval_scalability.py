"""Scalability and indexing verification for sparse and dense retrieval.

Verifies:
- BM25 inverted index postings list candidate pruning matches brute-force BM25.
- BM25 add, update (reconciliation), and query lifecycle.
- DenseRetriever pre-normalized dot product scoring matches cosine similarity.
- DenseRetriever add, update, and async search lifecycle.
- Deterministic tie-breaking across both sparse and dense engines.
"""
from __future__ import annotations

import math
from collections import Counter

import pytest

from verifyci.retrieval.dense import DenseRetriever, SearchResult, _cosine_similarity
from verifyci.retrieval.provider import HashEmbeddingProvider
from verifyci.retrieval.sparse import BM25Retriever, _B, _K1
from verifyci.retrieval.textnorm import tokenize


def _brute_force_bm25(
    corpus: dict[str, str], query: str, k: int = 10
) -> list[SearchResult]:
    """Reference brute-force BM25 scanning all documents without an inverted index."""
    query_tokens = tokenize(query)
    if not corpus or not query_tokens:
        return []

    doc_tokens = {doc_id: tokenize(text) for doc_id, text in corpus.items()}
    doc_tfs = {doc_id: Counter(tokens) for doc_id, tokens in doc_tokens.items()}
    doc_lengths = {doc_id: len(tokens) for doc_id, tokens in doc_tokens.items()}
    total = len(corpus)
    length_sum = sum(doc_lengths.values())
    avgdl = length_sum / total if total else 0.0

    df = Counter()
    for tokens in doc_tokens.values():
        for tok in set(tokens):
            df[tok] += 1

    results = []
    for doc_id, tf in doc_tfs.items():
        score = 0.0
        doc_len = doc_lengths[doc_id]
        for token in query_tokens:
            term_freq = tf.get(token, 0)
            if not term_freq:
                continue
            doc_df = df[token]
            idf = math.log((total - doc_df + 0.5) / (doc_df + 0.5) + 1)
            norm = term_freq + _K1 * (1 - _B + _B * doc_len / (avgdl or 1.0))
            score += idf * (term_freq * (_K1 + 1)) / norm
        if score > 0:
            results.append(SearchResult(id=doc_id, score=score, metadata={}))

    results.sort(key=lambda r: (-r.score, r.id))
    return results[:k]


def test_bm25_inverted_index_matches_brute_force_exact():
    corpus = {
        "doc1": "machine learning security vulnerability detection audit",
        "doc2": "software testing automated continuous integration pipeline",
        "doc3": "vulnerability scanning and audit report pipeline",
        "doc4": "deep learning neural network training pipeline",
        "doc5": "security audit compliance automated verification gate",
        "doc6": "completely unrelated cooking recipe for chocolate cake",
        "doc7": "astronomy star observation telescope galaxy nebula",
        "doc8": "pipeline continuous security compliance verification test",
    }

    retriever = BM25Retriever()
    for doc_id, text in corpus.items():
        retriever.add(doc_id, text)

    queries = [
        "pipeline security",
        "vulnerability audit",
        "continuous integration verification",
        "chocolate cake recipe",
        "nonexistent keyword query",
        "security security pipeline",
    ]

    for q in queries:
        actual = retriever.search(q, k=5)
        expected = _brute_force_bm25(corpus, q, k=5)

        assert len(actual) == len(expected), f"Query '{q}' length mismatch"
        for act, exp in zip(actual, expected):
            assert act.id == exp.id, f"Query '{q}' id mismatch: {act.id} vs {exp.id}"
            assert math.isclose(
                act.score, exp.score, rel_tol=1e-9
            ), f"Query '{q}' score mismatch: {act.score} vs {exp.score}"


def test_bm25_postings_prunes_zero_match_documents():
    retriever = BM25Retriever()
    retriever.add("d1", "apple orange")
    retriever.add("d2", "banana grape")
    retriever.add("d3", "cherry apple")

    # "apple" should only touch d1 and d3 postings
    postings = retriever._postings
    assert "apple" in postings
    postings_apple = {doc_id for doc_id, _ in postings["apple"]}
    assert postings_apple == {"d1", "d3"}

    hits = retriever.search("apple", k=10)
    hit_ids = {h.id for h in hits}
    assert hit_ids == {"d1", "d3"}
    assert "d2" not in hit_ids


def test_bm25_add_update_and_reconciliation():
    retriever = BM25Retriever()
    retriever.add("doc1", "first version with uniquealpha and commonword")
    retriever.add("doc2", "second doc with commonword only")

    # Initial query
    assert len(retriever.search("uniquealpha", k=5)) == 1
    assert retriever.search("uniquealpha", k=5)[0].id == "doc1"
    assert "uniquealpha" in retriever._postings
    assert "uniquealpha" in retriever._df

    # Update doc1: remove uniquealpha, introduce uniquebeta
    retriever.add("doc1", "updated version with uniquebeta and commonword")

    # uniquealpha should be cleanly pruned from postings and df
    assert "uniquealpha" not in retriever._postings
    assert "uniquealpha" not in retriever._df
    assert retriever.search("uniquealpha", k=5) == []

    # uniquebeta should now match doc1
    beta_hits = retriever.search("uniquebeta", k=5)
    assert len(beta_hits) == 1
    assert beta_hits[0].id == "doc1"

    # commonword should still match both docs without double counting
    assert retriever._df["commonword"] == 2
    common_hits = retriever.search("commonword", k=5)
    assert len(common_hits) == 2


@pytest.mark.asyncio
async def test_dense_prenormalized_scoring_matches_cosine_similarity():
    provider = HashEmbeddingProvider(64)
    retriever = DenseRetriever(provider)

    texts = {
        "doc1": "quantum physics particle acceleration experiment",
        "doc2": "classical mechanics fluid dynamics viscosity",
        "doc3": "theoretical astrophysics gravitational wave relativity",
    }

    for doc_id, text in texts.items():
        retriever.add(doc_id, text, {"source": doc_id})

    await retriever.build_index()

    # Verify unit norm of all precomputed embeddings
    for doc_id in texts:
        norm_emb = retriever._index[doc_id]["norm_embedding"]
        norm = sum(x * x for x in norm_emb) ** 0.5
        assert math.isclose(norm, 1.0, rel_tol=1e-5)

    query = "astrophysics gravitational relativity"
    hits = await retriever.search(query, k=3)

    query_emb = (await provider.embed([query]))[0]
    for hit in hits:
        doc_raw_emb = retriever._index[hit.id]["embedding"]
        raw_cos = _cosine_similarity(query_emb, doc_raw_emb)
        assert math.isclose(
            hit.score, raw_cos, rel_tol=1e-5
        ), f"Score mismatch for {hit.id}: {hit.score} vs {raw_cos}"


@pytest.mark.asyncio
async def test_dense_zero_vector_and_fallback():
    provider = HashEmbeddingProvider(3)
    retriever = DenseRetriever(provider)
    retriever.add("zero_doc", "dummy text", {}, embedding=[0.0, 0.0, 0.0])
    retriever.add("normal_doc", "normal text", {}, embedding=[1.0, 0.0, 0.0])

    hits = await retriever.search("anything", k=2)
    zero_hit = next(h for h in hits if h.id == "zero_doc")
    assert zero_hit.score == 0.0


@pytest.mark.asyncio
async def test_dense_document_update_lifecycle():
    provider = HashEmbeddingProvider(16)
    retriever = DenseRetriever(provider)

    vec_a = [1.0] + [0.0] * 15
    vec_b = [0.0, 1.0] + [0.0] * 14

    retriever.add("doc1", "text a", {}, embedding=vec_a)
    hits_a = await retriever.search("query", k=1)
    assert len(hits_a) == 1

    # Overwrite doc1 with vec_b
    retriever.add("doc1", "text b", {}, embedding=vec_b)
    await retriever.build_index()

    norm_b = retriever._index["doc1"]["norm_embedding"]
    assert math.isclose(norm_b[1], 1.0, rel_tol=1e-5)
    assert math.isclose(norm_b[0], 0.0, rel_tol=1e-5)
