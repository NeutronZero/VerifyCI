from verifyci.retrieval.sparse import BM25Retriever
from verifyci.retrieval.fusion import rrf_fusion
from verifyci.retrieval.dense import SearchResult


def test_bm25_retriever():
    retriever = BM25Retriever()
    retriever.add("doc1", "authentication login password")
    retriever.add("doc2", "database query sql")
    retriever.add("doc3", "authentication oauth token")

    results = retriever.search("authentication", k=2)
    assert len(results) == 2
    assert results[0].id == "doc1"


def test_bm25_no_match_returns_empty():
    retriever = BM25Retriever()
    retriever.add("doc1", "authentication login password")
    retriever.add("doc2", "database query sql")
    assert retriever.search("xylophone zebras", k=2) == []


def test_rrf_fusion():
    dense = [SearchResult(id="a", score=0.9, metadata={}), SearchResult(id="b", score=0.8, metadata={})]
    sparse = [SearchResult(id="b", score=0.9, metadata={}), SearchResult(id="c", score=0.8, metadata={})]
    graph = [SearchResult(id="a", score=0.7, metadata={}), SearchResult(id="c", score=0.6, metadata={})]

    result = rrf_fusion(dense, sparse, graph)
    assert "a" in result
    assert "b" in result
    assert "c" in result
