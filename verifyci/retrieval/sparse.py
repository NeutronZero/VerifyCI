import math
from collections import Counter

from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.textnorm import tokenize

_K1 = 1.5
_B = 0.75


class BM25Retriever:
    """BM25 over an incrementally built document set.

    Term frequencies are computed once at add() and stored; search()
    reads them without re-tokenizing or re-counting any document, so a
    query costs O(query terms x corpus) arithmetic, not O(corpus)
    Counter builds (the old code built a fresh Counter(tokens) per
    document per query). Re-adding an id replaces its text and
    reconciles document frequency exactly (the old code double-counted
    df on re-add and left a stale tf).
    """

    def __init__(self):
        self._documents = {}
        self._tf = {}          # id -> Counter(tokens)
        self._distinct = {}    # id -> set(tokens), drives df
        self._lengths = {}     # id -> doc length
        self._df = Counter()   # token -> number of documents containing it
        self._length_sum = 0

    @property
    def _avgdl(self):
        n = len(self._documents)
        return self._length_sum / n if n else 0.0

    def add(self, id: str, text: str):
        tokens = tokenize(text)
        tf = Counter(tokens)
        distinct = set(tokens)
        if id in self._documents:
            old_distinct = self._distinct[id]
            for token in old_distinct - distinct:
                self._df[token] -= 1
                if self._df[token] <= 0:
                    del self._df[token]
            for token in distinct - old_distinct:
                self._df[token] += 1
            self._length_sum -= self._lengths[id]
        else:
            for token in distinct:
                self._df[token] += 1
        self._documents[id] = text
        self._tf[id] = tf
        self._distinct[id] = distinct
        self._lengths[id] = len(tokens)
        self._length_sum += len(tokens)

    def search(self, query: str, k: int = 10) -> list[SearchResult]:
        query_tokens = tokenize(query)
        if not self._documents or not query_tokens:
            return []
        total = len(self._documents)
        avgdl = self._avgdl or 1.0
        results = []
        for id, tf in self._tf.items():
            score = 0.0
            doc_len = self._lengths[id]
            for token in query_tokens:
                term_freq = tf.get(token, 0)
                if not term_freq:
                    continue
                df = self._df[token]
                idf = math.log((total - df + 0.5) / (df + 0.5) + 1)
                norm = term_freq + _K1 * (1 - _B + _B * doc_len / avgdl)
                score += idf * (term_freq * (_K1 + 1)) / norm
            # Zero-score documents matched nothing: emitting them lets a
            # query with no hits return k arbitrary documents that earn
            # full RRF credit downstream.
            if score > 0:
                results.append(SearchResult(id=id, score=score, metadata={}))
        results.sort(key=lambda r: (-r.score, r.id))
        return results[:k]
