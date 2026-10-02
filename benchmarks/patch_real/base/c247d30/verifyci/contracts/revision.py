from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Revision:
    revision_id: str
    repository_id: str
    commit_id: Optional[str]
    parent_revision_id: Optional[str]
    source_hash: str
    timestamp: float
    ingestion_config_hash: str
