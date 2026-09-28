from src.memory.ledger import EventLedger
from src.memory.replay import ReplayEngine
from src.memory.snapshot import SnapshotStore


def test_event_ledger_append():
    ledger = EventLedger()
    event = ledger.append(
        type="TASK_CREATED",
        payload={"goal": "test"},
        provenance={"source": "test"},
    )
    assert event.id is not None
    assert event.type == "TASK_CREATED"
    assert event.prev_event_hash is None


def test_event_ledger_chain():
    ledger = EventLedger()
    e1 = ledger.append(type="TASK_CREATED", payload={}, provenance={})
    e2 = ledger.append(type="TOOL_CALLED", payload={}, provenance={})
    assert e2.prev_event_hash is not None
    assert e2.prev_event_hash != e1.prev_event_hash


def test_event_ledger_verify():
    ledger = EventLedger()
    ledger.append(type="TASK_CREATED", payload={}, provenance={})
    ledger.append(type="TOOL_CALLED", payload={}, provenance={})
    assert ledger.verify_chain() is True


def test_replay_engine():
    engine = ReplayEngine()
    engine.add_anchor("rev1", {"state": "initial"})
    engine.add_delta("rev1", "rev2", {"new_key": "new_value"})

    result = engine.replay("rev1", "rev2")
    assert result.state["state"] == "initial"
    assert result.state["new_key"] == "new_value"


def test_snapshot_store():
    store = SnapshotStore(snapshot_threshold=2)
    result1 = store.maybe_snapshot("rev1", {"state": "s1"})
    assert result1 is None
    result2 = store.maybe_snapshot("rev2", {"state": "s2"})
    assert result2 is not None
    assert result2.state["state"] == "s2"
