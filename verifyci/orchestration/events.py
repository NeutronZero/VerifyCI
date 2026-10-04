from typing import Any, Optional
from verifyci.contracts.event import Event
from verifyci.memory.ledger import EventLedger


def emit_event(
    ledger: Optional[EventLedger],
    type: str,
    payload: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    task_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
) -> Optional[Event]:
    if ledger is None:
        return None
    return ledger.append(
        type=type,
        payload=payload if payload is not None else {},
        provenance=provenance if provenance is not None else {},
        task_id=task_id,
        conversation_id=conversation_id,
    )
