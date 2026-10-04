import time
import uuid
from typing import Optional

from verifyci.contracts.event import Event
from verifyci.contracts.canonical import event_hash


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

    def verify_subchain(self, expected_head: Optional[str] = None,
                        expected_genesis: Optional[str] = None) -> bool:
        if expected_genesis is not None:
            if not self._events or self._events[0].prev_event_hash != expected_genesis:
                return False
        for i in range(1, len(self._events)):
            expected_hash = event_hash(self._events[i - 1])
            if self._events[i].prev_event_hash != expected_hash:
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

    def adopt(self, event: Event) -> Event:
        # Adopt an event created by another ledger (aggregate mirrors
        # share the same Event objects so ids and hashes match).
        self._events.append(event)
        return event


def verify_task_subchain(all_events: list, task_id: str | None,
                         expected_head: Optional[str] = None) -> bool:
    """Task-scoped chain check: unrelated events must not participate.

    The events table is a global interleaved log written by per-task
    ledgers (see `anchor.py`), so a task event's `prev_event_hash`
    references its predecessor *within the task*, never the previous
    global event. Hence:
    - the first stored event of the task must carry no prev hash;
    - every later task event must reference the immediately preceding
      event of the same task, in stored order;
    - events of other tasks are filtered out entirely, so tampering in
      one chain can neither break another chain nor be hidden by it.

    Truncation is still caught: dropping a task's first event leaves
    its successor with a non-None prev hash; dropping the last breaks
    the pinned head. A forged event inserted mid-chain breaks the next
    link because the real successor's prev names the original.
    """
    wanted = task_id or ""
    task_events = [e for e in all_events if (e.task_id or "") == wanted]
    if not task_events:
        return False
    if task_events[0].prev_event_hash is not None:
        return False
    for i in range(1, len(task_events)):
        if task_events[i].prev_event_hash != event_hash(task_events[i - 1]):
            return False
    if expected_head is not None:
        if event_hash(task_events[-1]) != expected_head:
            return False
    return True


def append_anchor(path: str, task_id: str, revision_id: str,
                  head_hash_value: str) -> dict:
    """Append one anchor line (L2 tamper-evidence log).

    JSONL, append-only, one object per line:
    ``{"task_id", "revision_id", "head_hash", "timestamp"}``. The anchor
    file must live in a different fault domain than the events DB to
    mean anything — an anchor next to the DB it vouches for is
    decoration. Callers, not this function, choose the domain.
    """
    import json as _json
    import time as _time
    record = {
        "task_id": task_id,
        "revision_id": revision_id or "",
        "head_hash": head_hash_value,
        "timestamp": _time.time(),
    }
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(_json.dumps(record, sort_keys=True) + "\n")
    return record


def read_anchors(path: str) -> tuple[list[dict], int]:
    """Read an anchor log as (well-formed records, malformed count).

    Blank lines are benign (trailing newlines) and skipped. Anything
    else that is not a JSON object with a `head_hash` — truncated
    writes, interleaved garbage, foreign records — counts as malformed.
    Callers fail closed on malformed > 0: verifying against the
    surviving prefix would silently vouch for an older head as if the
    newer write never happened, which is exactly the false negative
    the anchor log exists to prevent. A missing file is ([], 0), not
    corruption — absence and damage fail through different errors.
    """
    import json as _json
    records: list[dict] = []
    malformed = 0
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = _json.loads(line)
                except ValueError:
                    malformed += 1
                    continue
                if isinstance(record, dict) and record.get("head_hash"):
                    records.append(record)
                else:
                    malformed += 1
    except FileNotFoundError:
        pass
    return records, malformed
