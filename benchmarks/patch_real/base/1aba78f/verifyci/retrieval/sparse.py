import math
from collections import Counter
from dataclasses import dataclass

from verifyci.retrieval.dense import SearchResult
from verifyci.retrieval.textnorm import tokenize


@dataclass
class BM25Index:
    documents: dict[str, str]
    avgdl: float
    k1: float = 1.5
    b: float = 0.75


class BM25Retriever:
    def __init__(self):
        self._documents = {}
        self._tokenized = {}
        self._df = Counter()
        self._avgdl = 0.0

    def add(self, id: str, text: str):
        tokens = tokenize(text)
        self._documents[id] = text
        self._tokenized[id] = tokens
        self._avgdl = (self._avgdl * (len(self._documents) - 1) + len(tokens)) / len(self._documents)
        for token in set(tokens):
            self._df[token] += 1

    def search(self, query: str, k: int = 10) -> list[SearchResult]:
        query_tokens = tokenize(query)
        results = []
        for id, tokens in self._tokenized.items():
            score = 0.0
            tf = Counter(tokens)
            for token in query_tokens:
                if token not in tf:
                    continue
                idf = math.log((len(self._documents) - self._df[token] + 0.5) / (self._df[token] + 0.5) + 1)
                score += idf * (tf[token] * 2.5) / (tf[token] + 1.5 * (1 - 0.75 + 0.75 * len(tokens) / self._avgdl))
            # Zero-score documents matched nothing: emitting them lets a
            # query with no hits return k arbitrary documents that earn
            # full RRF credit downstream.
            if score > 0:
                results.append(SearchResult(id=id, score=score, metadata={}))
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:k]
