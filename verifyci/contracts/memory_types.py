from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProjectionState:
    projection_id: str
    revision_id: str
    state: dict[str, Any]
    timestamp: float
