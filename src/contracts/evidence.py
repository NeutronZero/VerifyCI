from dataclasses import dataclass
from typing import Any, Optional

from src.contracts.entity import Entity
from src.contracts.edge import Edge
from src.contracts.verification_ir import BlastRadiusResult


@dataclass(frozen=True)
class SourceChunk:
    chunk_id: str
    file_path: str
    line_start: int
    line_end: int
    content: str
    source_hash: str


@dataclass(frozen=True)
class ProvenanceEntry:
    entry_id: str
    entity_id: Optional[str]
    file_path: str
    line_start: int
    line_end: int
    source_hash: str
    revision_id: str


@dataclass(frozen=True)
class EvidencePack:
    query: str
    entities: list[Entity]
    relationships: list[Edge]
    source_chunks: list[SourceChunk]
    provenance: list[ProvenanceEntry]
    scores: dict[str, float]
    retrieval_methods: list[str]
    retrieval_timestamp: float
    graph_revision: str
    blast_radius: Optional[BlastRadiusResult] = None
    verification_metadata: Optional[dict[str, Any]] = None
