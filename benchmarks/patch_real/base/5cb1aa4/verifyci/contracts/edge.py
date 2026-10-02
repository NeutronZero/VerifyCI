from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EdgeType(Enum):
    CONTAINS = "CONTAINS"
    CALLS = "CALLS"
    #: A call reference observed at extraction whose callee is not defined
    #: in the same file. `dst_entity_id` is empty; `metadata` carries
    #: `callee` (name) and `caller_scope`. A post-build resolver links
    #: these once the full entity set is known; the builder never adds
    #: them as graph links.
    CALLS_UNRESOLVED = "CALLS_UNRESOLVED"
    #: Same shape for a base class not defined in the same file
    #: (`metadata["base"]`).
    INHERITS_UNRESOLVED = "INHERITS_UNRESOLVED"
    IMPORTS = "IMPORTS"
    INHERITS = "INHERITS"
    IMPLEMENTS = "IMPLEMENTS"
    REFERENCES = "REFERENCES"
    DEFINES = "DEFINES"
    USES = "USES"
    RETURNS = "RETURNS"
    DECORATES = "DECORATES"
    DOCUMENTS = "DOCUMENTS"
    DEPENDS_ON = "DEPENDS_ON"


class CPGEdgeSubtype(Enum):
    CONTAINS = "contains"
    HAS_NAME = "has_name"
    CALLS_DIRECT = "calls_direct"
    CALLS_INDIRECT = "calls_indirect"
    CALLS_RECURSIVE = "calls_recursive"
    IMPORTS = "imports"
    INHERITS = "inherits"
    REFERENCES = "references"
    CONTROLS = "controls"
    FLOWS_TO = "flows_to"
    SEQUENTIAL = "sequential"
    REACHES = "reaches"
    USES = "uses"
    DEFINES = "defines"


@dataclass(frozen=True)
class Edge:
    """
    Temporal fields:
    - valid_from / valid_until:   VALID TIME — when the fact was true in the code.
    - t_created / t_expired:      TRANSACTION TIME — when the platform recorded
                                  or retracted the fact.
    Bitemporal model (Graphiti convention). Both pairs required. Do not merge.
    """
    id: str
    revision_id: str
    src_entity_id: str
    dst_entity_id: str
    type: EdgeType
    subtype: Optional[CPGEdgeSubtype] = None
    valid_from: Optional[float] = None
    valid_until: Optional[float] = None
    observed_at: float = 0.0
    source_commit: Optional[str] = None
    t_created: Optional[float] = None
    t_expired: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    properties_json: Optional[str] = None
