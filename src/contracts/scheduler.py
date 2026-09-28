from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskStatus(Enum):
    """Execution status. Terminal: COMPLETED, FAILED, CANCELLED,
    HUMAN_REVIEW, INCONCLUSIVE.

    HUMAN_REVIEW / INCONCLUSIVE are terminal execution states meaning the
    run stopped at a verification gate. The verification outcome itself
    lives on VerificationDecision (see scheduler.decision()); execution
    status never conflates with it.
    """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    INCONCLUSIVE = "INCONCLUSIVE"


TERMINAL_STATUSES = frozenset({
    TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED,
    TaskStatus.HUMAN_REVIEW, TaskStatus.INCONCLUSIVE,
})


@dataclass(frozen=True)
class ExecutableDAG:
    dag_id: str
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)
    task_id: str = ""
    conversation_id: str = ""
    budget_nano_usd: int = 0


class Scheduler(ABC):
    @abstractmethod
    async def submit(self, dag: Any) -> str: ...

    @abstractmethod
    async def status(self, task_id: str) -> TaskStatus: ...

    @abstractmethod
    async def cancel(self, task_id: str): ...

    @abstractmethod
    async def resume(self, task_id: str): ...


class DurableScheduler(Scheduler):
    @abstractmethod
    async def recover(self, task_id: str) -> bool: ...
