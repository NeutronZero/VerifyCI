from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str = ""
    deterministic: bool = True


@dataclass(frozen=True)
class ToolResult:
    tool_name: str
    output: Any
    provenance: dict[str, Any] = field(default_factory=dict)


class Tool(ABC):
    definition: ToolDefinition

    @abstractmethod
    async def run(self, **kwargs: Any) -> ToolResult: ...
