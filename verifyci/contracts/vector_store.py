from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VectorRecord:
    id: str
    embedding: list[float]
    metadata: dict[str, Any] = field(default_factory=dict)


class VectorStore(ABC):
    @abstractmethod
    def upsert(self, records: list[VectorRecord]) -> None: ...

    @abstractmethod
    def search(self, embedding: list[float], k: int = 10) -> list[tuple[str, float]]: ...


class InMemoryVectorStore(VectorStore):
    def __init__(self) -> None:
        self._records: dict[str, VectorRecord] = {}

    def upsert(self, records: list[VectorRecord]) -> None:
        for r in records:
            self._records[r.id] = r

    def search(self, embedding: list[float], k: int = 10) -> list[tuple[str, float]]:
        scored = [(rid, _cosine(rec.embedding, embedding)) for rid, rec in self._records.items()]
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:k]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0
