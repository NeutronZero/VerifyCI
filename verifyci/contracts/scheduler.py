from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskStatus(Enum):
    """Execution status. Terminal: COMPLETED, FAILED, CANCELLED,
    HUMAN_REVIEW, INCONCLUSIVE, TIMEOUT.

    HUMAN_REVIEW / INCONCLUSIVE are terminal execution states meaning the
    run stopped at a verification gate. The verification outcome itself
    lives on VerificationDecision (see scheduler.decision()); execution
    status never conflates with it.

    TIMEOUT is terminal execution state meaning a node exceeded its
    deadline (exit 3 infrastructure channel, never a FAIL verdict).
    UNKNOWN is terminal-by-convention: the scheduler holds no record of
    the task id (never submitted or already evicted), so there is nothing
    to poll — wait loops return it immediately instead of polling to
    expiry. Neither is a verification verdict.
    """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    INCONCLUSIVE = "INCONCLUSIVE"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"


TERMINAL_STATUSES = frozenset({
    TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED,
    TaskStatus.HUMAN_REVIEW, TaskStatus.INCONCLUSIVE,
    TaskStatus.TIMEOUT, TaskStatus.UNKNOWN,
})


@dataclass(frozen=True)
class ExecutableDAG:
    dag_id: str
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[tuple[str, str]] = field(default_factory=list)
    task_id: str = ""
    conversation_id: str = ""
    # None means "no budget set" (unlimited). 0 is a real zero budget:
    # any node breaches it. The old default of 0 silently disabled the
    # guard because `if budget` is falsy for 0.
    budget_nano_usd: int | None = None


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
