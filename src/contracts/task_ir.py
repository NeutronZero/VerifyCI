from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Constraint:
    constraint_id: str
    type: str
    expression: str


@dataclass(frozen=True)
class Budget:
    budget_id: str
    nano_usd: int
    spent: int = 0

    def remaining(self) -> int:
        return self.nano_usd - self.spent


@dataclass(frozen=True)
class Step:
    step_id: str
    type: str
    config: dict[str, Any]
    pre_commit_hook_id: Optional[str] = None
    depends_on: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class NodeResult:
    step_id: str
    status: str
    output: Any = None
    diff: Optional[str] = None


@dataclass(frozen=True)
class TaskIR:
    goal: str
    intent_package_id: str
    steps: list[Step]
    constraints: list[Constraint]
    budget: Budget
    policy_id: str
