import pytest

from verifyci.retrieval.dense import DenseRetriever
from verifyci.retrieval.provider import HashEmbeddingProvider


@pytest.mark.asyncio
async def test_dense_retriever_empty():
    retriever = DenseRetriever(HashEmbeddingProvider(64))
    hits = await retriever.search("anything")
    assert hits == []


@pytest.mark.asyncio
async def test_dense_retriever_batch_and_search():
    provider = HashEmbeddingProvider(128)
    retriever = DenseRetriever(provider)
    retriever.add("doc1", "user login authentication token", {"category": "auth"})
    retriever.add("doc2", "database query connection pool", {"category": "db"})
    retriever.add("doc3", "react frontend component button", {"category": "ui"})

    hits = await retriever.search("auth token login", k=2)
    assert len(hits) == 2
    assert hits[0].id == "doc1"
    assert hits[0].metadata["category"] == "auth"
    assert hits[0].score > hits[1].score


@pytest.mark.asyncio
async def test_dense_retriever_precomputed_embeddings():
    provider = HashEmbeddingProvider(64)
    vec1 = (await provider.embed(["exact match"]))[0]
    retriever = DenseRetriever(provider)
    retriever.add("doc1", "exact match", {}, embedding=vec1)
    retriever.add("doc2", "completely unrelated content", {})

    hits = await retriever.search("exact match", k=1)
    assert len(hits) == 1
    assert hits[0].id == "doc1"
    assert hits[0].score >= 0.99
