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

    def head_hash(self) -> Optional[str]:
        """Hash of the latest event. The chain links each event to its
        predecessor, so the *last* event is anchored by nothing — anyone
        holding the DB can rewrite it and the links still check out. The
        only fix is pinning the head externally (operator notebook, a
        second store, a signed checkpoint) and verifying against it."""
        if not self._events:
            return None
        return event_hash(self._events[-1])

    def verify_chain(self, expected_head: Optional[str] = None) -> bool:
        for i, event in enumerate(self._events):
            if i == 0:
                if event.prev_event_hash is not None:
                    return False
                continue
            expected_hash = event_hash(self._events[i - 1])
            if event.prev_event_hash != expected_hash:
                return False
        if expected_head is not None:
            if not self._events or event_hash(self._events[-1]) != expected_head:
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
