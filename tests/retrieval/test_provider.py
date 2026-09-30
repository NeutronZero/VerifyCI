"""Embedding provider selection, batching, and the content cache.

Everything here runs offline: the cache wraps the hash provider, the
Ollama provider is never constructed against a server (selection only),
and batch chunking is pinned through a stubbed transport.
"""
import asyncio

from verifyci.retrieval.provider import (
    CachedEmbeddingProvider,
    HashEmbeddingProvider,
    OllamaEmbeddingProvider,
    default_dense_provider,
)


class _Counting(HashEmbeddingProvider):
    def __init__(self):
        super().__init__()
        self.calls = 0

    async def embed(self, texts):
        self.calls += 1
        return await super().embed(texts)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_cache_dedupes_within_and_across_calls(tmp_path):
    base = _Counting()
    provider = CachedEmbeddingProvider(base, str(tmp_path / "cache.json"))
    first = _run(provider.embed(["alpha", "beta", "alpha"]))
    assert base.calls == 1
    second = _run(provider.embed(["beta", "alpha"]))
    assert base.calls == 1
    assert first[0] == second[1] == first[2]
    assert provider.model_name() == "cached:offline-hash-256"


def test_cache_persists_across_instances(tmp_path):
    path = str(tmp_path / "cache.json")
    _run(CachedEmbeddingProvider(_Counting(), path).embed(["alpha"]))
    base = _Counting()
    vecs = _run(CachedEmbeddingProvider(base, path).embed(["alpha"]))
    assert base.calls == 0
    assert len(vecs[0]) == 256


def test_cache_rebuilds_on_corrupt_file(tmp_path):
    path = str(tmp_path / "cache.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("{not json")
    base = _Counting()
    vecs = _run(CachedEmbeddingProvider(base, path).embed(["alpha"]))
    assert base.calls == 1
    assert len(vecs[0]) == 256


def test_cache_memory_only_without_path():
    provider = CachedEmbeddingProvider(_Counting(), None)
    _run(provider.embed(["alpha"]))
    assert provider.cache_path is None


def test_selection_defaults_to_hash(monkeypatch):
    monkeypatch.delenv("ACI_EMBEDDINGS", raising=False)
    provider = default_dense_provider()
    assert isinstance(provider, HashEmbeddingProvider)


def test_selection_unknown_spec_raises(monkeypatch):
    monkeypatch.setenv("ACI_EMBEDDINGS", "bert")
    try:
        default_dense_provider()
    except ValueError as e:
        assert "ACI_EMBEDDINGS" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_selection_ollama_parses_model(monkeypatch, tmp_path):
    monkeypatch.setenv("ACI_EMBEDDINGS", "ollama:mxbai-embed-large")
    monkeypatch.setenv("ACI_OLLAMA_URL", "http://example:11434")
    provider = default_dense_provider(str(tmp_path))
    assert isinstance(provider, CachedEmbeddingProvider)
    assert isinstance(provider.base, OllamaEmbeddingProvider)
    assert provider.base.model == "mxbai-embed-large"
    assert provider.base.base_url == "http://example:11434"
    assert provider.cache_path.endswith("embedding_cache_mxbai_embed_large.json")


def test_selection_ollama_defaults(monkeypatch):
    monkeypatch.setenv("ACI_EMBEDDINGS", "ollama")
    monkeypatch.delenv("ACI_OLLAMA_URL", raising=False)
    provider = default_dense_provider()
    assert isinstance(provider, CachedEmbeddingProvider)
    assert provider.base.model == "nomic-embed-text"
    assert provider.cache_path is None


def test_batching_chunks_requests():
    seen = []

    class _Stub(OllamaEmbeddingProvider):
        async def _embed_batch(self, texts):
            seen.append(len(texts))
            return [[float(i)] for i in range(len(texts))]

    provider = _Stub(batch_size=64)
    vecs = _run(provider.embed(["t%d" % i for i in range(150)]))
    assert seen == [64, 64, 22]
    assert len(vecs) == 150
    assert _run(provider.embed([])) == []
