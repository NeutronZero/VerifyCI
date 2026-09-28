import time
import uuid
from typing import Optional

from src.contracts.event import Event
from src.contracts.canonical import event_hash


class EventLedger:
    def __init__(self):
        self._events = []

    def append(
        self,
        type: str,
        payload: dict,
        provenance: dict,
        task_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
    ) -> Event:
        event = Event(
            id=str(uuid.uuid4()),
            type=type,
            timestamp=time.time(),
            task_id=task_id,
            conversation_id=conversation_id,
            payload=payload,
            provenance=provenance,
            prev_event_hash=self._last_hash(),
        )
        self._events.append(event)
        return event

    def get_events(self) -> list[Event]:
        return list(self._events)

    def verify_chain(self) -> bool:
        for i, event in enumerate(self._events):
            if i == 0:
                if event.prev_event_hash is not None:
                    return False
                continue
            expected_hash = event_hash(self._events[i - 1])
            if event.prev_event_hash != expected_hash:
                return False
        return True

    def save_to_store(self, store) -> int:
        for event in self._events:
            store.insert_event(event)
        return len(self._events)

    @classmethod
    def load_from_store(cls, store) -> "EventLedger":
        ledger = cls()
        ledger._events = list(store.get_events())
        return ledger

    def _last_hash(self) -> Optional[str]:
        if not self._events:
            return None
        return event_hash(self._events[-1])
