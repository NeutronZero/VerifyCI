"""VERIFYCI_* is canonical; ACI_* is the legacy fallback.

Precedence is by presence: a set VERIFYCI_<NAME> wins even when its
value is empty, and ACI_<NAME> still works for operators who have not
migrated. A misconfigured operator finds out loudly, not via a silently
wrong default.
"""
from verifyci.env import get_env


def test_canonical_prefix_read(monkeypatch):
    monkeypatch.setenv("VERIFYCI_API_TOKEN", "newstyle")
    assert get_env("API_TOKEN", "") == "newstyle"


def test_legacy_fallback_still_honored(monkeypatch):
    monkeypatch.delenv("VERIFYCI_API_TOKEN", raising=False)
    monkeypatch.setenv("ACI_API_TOKEN", "oldstyle")
    assert get_env("API_TOKEN", "") == "oldstyle"


def test_canonical_wins_when_both_set(monkeypatch):
    monkeypatch.setenv("VERIFYCI_EMBEDDINGS", "hash")
    monkeypatch.setenv("ACI_EMBEDDINGS", "bert")
    assert get_env("EMBEDDINGS", "hash") == "hash"


def test_empty_canonical_value_not_shadowed_by_legacy(monkeypatch):
    # Presence decides: an explicitly-empty VERIFYCI_ token means
    # "unset", which the http gate depends on; ACI_ must not leak back in.
    monkeypatch.setenv("VERIFYCI_API_TOKEN", "")
    monkeypatch.setenv("ACI_API_TOKEN", "sneaky")
    assert get_env("API_TOKEN", "") == ""


def test_default_when_neither_set(monkeypatch):
    monkeypatch.delenv("VERIFYCI_API_TOKEN", raising=False)
    monkeypatch.delenv("ACI_API_TOKEN", raising=False)
    assert get_env("API_TOKEN", "fallback") == "fallback"


def test_http_token_honors_canonical_name(monkeypatch):
    from verifyci.interface.http import _api_token
    monkeypatch.delenv("ACI_API_TOKEN", raising=False)
    monkeypatch.setenv("VERIFYCI_API_TOKEN", "canon")
    assert _api_token() == "canon"


def test_provider_selection_honors_canonical_name(monkeypatch):
    from verifyci.retrieval.provider import (
        CachedEmbeddingProvider, HashEmbeddingProvider, OllamaEmbeddingProvider,
        default_dense_provider)
    monkeypatch.delenv("ACI_EMBEDDINGS", raising=False)
    monkeypatch.delenv("ACI_OLLAMA_URL", raising=False)
    monkeypatch.setenv("VERIFYCI_EMBEDDINGS", "ollama:mxbai-embed-large")
    monkeypatch.setenv("VERIFYCI_OLLAMA_URL", "http://example:11434")
    provider = default_dense_provider()
    assert isinstance(provider, CachedEmbeddingProvider)
    assert isinstance(provider.base, OllamaEmbeddingProvider)
    assert provider.base.base_url == "http://example:11434"
    monkeypatch.setenv("VERIFYCI_EMBEDDINGS", "")
    assert isinstance(default_dense_provider(), HashEmbeddingProvider)
