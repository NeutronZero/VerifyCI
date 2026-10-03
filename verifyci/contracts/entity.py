from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EntityType(Enum):
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    PARAMETER = "PARAMETER"
    VARIABLE = "VARIABLE"
    TYPE = "TYPE"
    IMPORT = "IMPORT"


class GraphType(Enum):
    AST_DERIVED_CPG = "ast_derived_cpg"
    FULL_CPG = "full_cpg"


@dataclass(frozen=True)
class EntitySnippetRecord:
    lines: tuple[str, ...]
    is_complete: bool  # True ONLY if snippet encompasses 100% of entity span
    truncated_at_line: Optional[int]  # 1-based line where truncation occurred, if any
    char_count: int
    encoding: str = "utf-8"

    def __init__(
        self,
        lines: tuple[str, ...] | list[str],
        is_complete: bool,
        truncated_at_line: Optional[int],
        char_count: int,
        encoding: str = "utf-8",
    ):
        object.__setattr__(self, "lines", tuple(lines))
        object.__setattr__(self, "is_complete", is_complete)
        object.__setattr__(self, "truncated_at_line", truncated_at_line)
        object.__setattr__(self, "char_count", char_count)
        object.__setattr__(self, "encoding", encoding)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@dataclass(frozen=True)
class Entity:
    """
    Temporal fields:
    - valid_from / valid_until:   VALID TIME — when the fact was true in the code.
    - t_created / t_expired:      TRANSACTION TIME — when the platform recorded
                                  or retracted the fact.
    Bitemporal model (Graphiti convention). Both pairs required. Do not merge.
    """
    repository_id: str
    logical_entity_id: str
    revision_entity_id: str
    type: EntityType
    name: str
    file_path: str
    line_start: int
    line_end: int
    language: str
    source_hash: str
    revision_id: str
    valid_from: Optional[float] = None
    valid_until: Optional[float] = None
    t_created: Optional[float] = None
    t_expired: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    properties_json: Optional[str] = None

    def provenance_chain(self) -> list[str]:
        return [
            self.source_hash,
            self.revision_id,
            self.file_path,
            f"{self.line_start}-{self.line_end}",
        ]
