from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RetrievalQuery:
    text: str
    k: int = 10
    seed_entity_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RetrievalHit:
    id: str
    score: float
    method: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class Retriever(ABC):
    @abstractmethod
    def retrieve(self, query: RetrievalQuery) -> list[RetrievalHit]: ...
