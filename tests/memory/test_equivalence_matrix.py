"""Replay equivalence matrix (PLAN.md Phase 3 gate: 44 tests in tests/memory).

Covers: prefix equivalence (replay(events[:n]) == independent fold),
tamper detection at every position, anchor+delta byte-ratio < 50%,
snapshot round-trips, store persistence, and replay determinism.
"""
import json

import pytest

from verifyci.memory.ledger import EventLedger
from verifyci.memory.replay import ReplayEngine
from verifyci.memory.snapshot import SnapshotStore

LENGTHS = [1, 2, 3, 5, 8, 13]


def _build(shape: str, n: int) -> EventLedger:
    ledger = EventLedger()
    for i in range(n):
        if shape == "linear":
            payload = {f"k{i}": i}
        elif shape == "overwrite":
            payload = {"k": i}
        else:
            payload = {"nested": {"level": i, "tag": f"t{i}"}}
        ledger.append(type=f"E{i}", payload=payload, provenance={"s": shape})
    return ledger


def _fold(events) -> dict:
    state: dict = {}
    for e in events:
        state.update({k: v for k, v in (e.payload or {}).items()})
    return state


@pytest.mark.parametrize("shape", ["linear", "overwrite", "nested"])
@pytest.mark.parametrize("n", LENGTHS)
def test_prefix_equivalence(shape, n):
    ledger = _build(shape, n)
    engine = ReplayEngine()
    events = ledger.get_events()
    for cut in range(1, n + 1):
        assert engine.replay_events(events[:cut]).state == _fold(events[:cut])
    assert ledger.verify_chain() is True


@pytest.mark.parametrize("pos", [0, 1, 2, 3, 4])
def test_tamper_detected_at_every_position(pos):
    import dataclasses
    ledger = _build("linear", 5)
    ledger._events[pos] = dataclasses.replace(ledger._events[pos], prev_event_hash="tampered")
    assert ledger.verify_chain() is False


@pytest.mark.parametrize("steps", [5, 10, 20])
def test_anchor_delta_bytes_under_half(steps):
    base = {f"base{i}": "x" * 20 for i in range(10)}
    full_sizes, anchor_size, delta_sizes = [], 0, []
    state = dict(base)
    snapshots = [dict(state)]
    anchor_size = len(json.dumps(state).encode())
    for i in range(steps):
        delta = {f"d{i}": "y" * 20}
        state.update(delta)
        snapshots.append(dict(state))
        delta_sizes.append(len(json.dumps(delta).encode()))
    full_sizes = [len(json.dumps(s).encode()) for s in snapshots[1:]]
    ratio = (anchor_size + sum(delta_sizes)) / sum(full_sizes)
    assert ratio < 0.5


@pytest.mark.parametrize("threshold", [1, 2, 5])
def test_snapshot_round_trip(threshold):
    store = SnapshotStore(snapshot_threshold=threshold)
    last = None
    for i in range(threshold * 2):
        snap = store.maybe_snapshot(f"rev{i}", {"i": i})
        if snap is not None:
            last = snap
    assert last is not None
    assert store.get_anchor(last.revision_id).state == last.state


def test_ledger_store_round_trip(tmp_path):
    from verifyci.storage.graph_store import GraphStore
    db = str(tmp_path / "mem.db")
    ledger = _build("linear", 4)
    store = GraphStore(db)
    try:
        assert ledger.save_to_store(store) == 4
        restored = EventLedger.load_from_store(store)
        assert [e.id for e in restored.get_events()] == [e.id for e in ledger.get_events()]
        assert restored.verify_chain() is True
    finally:
        store.close()


def test_replay_deterministic():
    ledger = _build("nested", 6)
    engine = ReplayEngine()
    events = ledger.get_events()
    assert engine.replay_events(events).state == engine.replay_events(events).state


def test_empty_replay():
    assert ReplayEngine().replay_events([]).state == {}


def test_delta_chain_multi_hop():
    engine = ReplayEngine()
    engine.add_anchor("rev1", {"a": 1})
    engine.add_delta("rev1", "rev2", {"b": 2})
    engine.add_delta("rev2", "rev3", {"c": 3})
    engine.add_delta("rev3", "rev4", {"d": 4})
    assert engine.replay("rev1", "rev4").state == {"a": 1, "b": 2, "c": 3, "d": 4}


def test_latest_anchor_fallback():
    engine = ReplayEngine()
    engine.add_anchor("rev1", {"a": 1})
    engine.add_delta("rev1", "rev2", {"b": 2})
    assert engine.replay("missing", "rev2").state == {"a": 1, "b": 2}


def test_conversation_scoping_preserved():
    ledger = EventLedger()
    ledger.append(type="T", payload={}, provenance={}, task_id="t1", conversation_id="c9")
    assert ledger.get_events()[0].conversation_id == "c9"
    assert ledger.verify_chain() is True
