"""BM25 ranking semantics, tested independently of the fusion layer.

The fusion benchmark smoke scores are behavioral controls, not a
production retrieval gate; what is pinned here is the sparse scorer
itself: idf dominance, sublinear tf, length normalization, ordering,
k-truncation, and the rebuild contract (a search must not re-create
per-document term counters over the corpus on every query).
"""
from collections import Counter

import verifyci.retrieval.sparse as sparse_mod
from verifyci.retrieval.sparse import BM25Retriever


def _index(pairs):
    r = BM25Retriever()
    for i, t in pairs:
        r.add(i, t)
    return r


def test_rare_term_beats_common_term():
    r = _index([
        ("a", "needle haystack"),
        ("b", "haystack sand"),
        ("c", "haystack grass"),
        ("d", "haystack dirt"),
    ])
    ids = [h.id for h in r.search("needle haystack", k=4)]
    assert ids[0] == "a"  # a matches the rare term (high idf) and the common one


def test_tf_saturates_sublinearly():
    r = _index([
        ("one", "search"),
        ("twelve", " ".join(["search"] * 12)),
    ])
    one = next(h for h in r.search("search", k=2) if h.id == "one")
    twelve = next(h for h in r.search("search", k=2) if h.id == "twelve")
    assert twelve.score > one.score
    assert twelve.score < 4 * one.score  # k1=1.5 saturation, not linear


def test_length_normalization_favors_brief_match():
    r = _index([
        ("brief", "token stream"),
        ("long", "token stream " + "filler " * 40),
    ])
    hits = {h.id: h.score for h in r.search("token stream", k=2)}
    assert hits["brief"] > hits["long"]


def test_zero_match_excluded_and_truncated():
    r = _index([(str(i), f"doc{i} common") for i in range(10)])
    assert r.search("xylophone", k=5) == []
    assert len(r.search("common", k=3)) == 3
    scores = [h.score for h in r.search("common", k=10)]
    assert scores == sorted(scores, reverse=True)


def test_search_builds_no_per_document_counters():
    # The per-query corpus rebuild: search() re-created Counter(tokens)
    # for every document on every query (measured: 50 constructions for
    # a 50-doc index). tf must be stored at add-time.
    r = _index([(str(i), "alpha beta") for i in range(50)])
    real = Counter
    n = {"c": 0}

    def counting(*a, **k):
        n["c"] += 1
        return real(*a, **k)

    sparse_mod.Counter = counting  # ty: ignore[invalid-assignment] — deliberate constructor spy for call counting
    try:
        hits = r.search("alpha", k=100)
    finally:
        sparse_mod.Counter = real
    assert n["c"] == 0, f"search rebuilt {n['c']} Counters"
    assert len(hits) == 50


def test_readd_updates_counter_not_dupes_it():
    r = BM25Retriever()
    r.add("d", "alpha")
    r.add("d", "alpha beta gamma")
    hits = {h.id: h.score for h in r.search("gamma", k=5)}
    assert "d" in hits  # tf reflects the latest text, not a stale Counter
