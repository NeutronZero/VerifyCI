"""H1 failing-first representation contract (MUST FAIL pre-implementation).

Encodes the intended `build_doc_text` contract for H1-B/C/D: enriched
document text MUST carry the entity's own signature/docstring terms
(leakage-free: name, path, signature, docstring only — never qrels,
queries, labels, or benchmark metadata) while preserving the frozen
`name file_path` identity prefix. These tests fail until the builder
exists; no retriever changes happen first.
"""
import pytest


def _builder():
    from verifyci.retrieval.representation import build_doc_text
    return build_doc_text


ENTITY = {
    "name": "authenticate_user",
    "file_path": "auth.py",
    "signature": "authenticate_user(token: str) -> User",
    "docstring": "Validate an access token and return the authenticated user.",
}


def test_enriched_text_preserves_frozen_identity():
    build_doc_text = _builder()
    text = build_doc_text(**ENTITY)
    assert text.startswith("authenticate_user auth.py"), text


def test_enriched_text_carries_signature_terms():
    build_doc_text = _builder()
    text = build_doc_text(**ENTITY)
    assert "token" in text and "User" in text, text


def test_enriched_text_carries_docstring_terms():
    build_doc_text = _builder()
    text = build_doc_text(**ENTITY)
    assert "Validate an access token" in text, text


def test_enriched_text_never_empty_without_enrichment():
    # Degenerate input degrades to the frozen format, never to an
    # empty (unjudgeable, validator-rejected) document.
    pytest.importorskip("verifyci.retrieval.representation")
    from verifyci.retrieval.representation import build_doc_text
    assert build_doc_text(name="f", file_path="a.py") == "f a.py"


def test_distinctive_terms_retrieve_enriched_doc():
    # End-to-end contract: a query of docstring-distinctive terms ranks
    # the enriched doc top-1 under BM25 (the sparse channel H1 enriches).
    from verifyci.retrieval.representation import build_doc_text
    from verifyci.retrieval.sparse import BM25Retriever
    docs = {
        "target": build_doc_text(**ENTITY),
        "other": build_doc_text(
            name="hash_password", file_path="auth.py",
            signature="hash_password(pw: str) -> str",
            docstring="Stretch a password with a slow salted hash."),
    }
    bm25 = BM25Retriever()
    for did, text in docs.items():
        bm25.add(did, text)
    hits = bm25.search("Validate an access token", k=2)
    assert [h.id for h in hits][0] == "target"
