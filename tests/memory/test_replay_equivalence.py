import pytest

from verifyci.memory.ledger import EventLedger
from verifyci.memory.replay import ReplayEngine


def test_replay_prefix_equivalence():
    engine = ReplayEngine()
    engine.add_anchor("rev0", {})
    engine.add_delta("rev0", "rev1", {"a": 1})
    engine.add_delta("rev1", "rev2", {"b": 2})
    full = engine.replay("rev0", "rev2")
    step1 = engine.replay("rev0", "rev1")
    assert step1.state == {"a": 1}
    assert full.state == {"a": 1, "b": 2}


def test_replay_events_folds_payloads():
    ledger = EventLedger()
    ledger.append(type="E1", payload={"goal": "g"}, provenance={})
    ledger.append(type="E2", payload={"outcome": "ok"}, provenance={})
    engine = ReplayEngine()
    state = engine.replay_events(ledger.get_events())
    assert state.state["goal"] == "g"
    assert state.state["outcome"] == "ok"


def test_replay_events_equal_timestamps_keep_arrival_order():
    # Coarse clocks (Windows ~15ms granularity) stamp fast-appended events
    # with identical timestamps while ids are random uuids: ordering must
    # be stable on arrival order, never scrambled by an id tiebreak.
    import dataclasses
    from verifyci.contracts.event import Event
    base = [Event(id=f"id-{i}", type="E", timestamp=1.0, task_id=None,
                  conversation_id=None, payload={"k": i}, provenance={},
                  prev_event_hash=None, attestation=None)
            for i in range(5)]
    engine = ReplayEngine()
    assert engine.replay_events(base).state == {"k": 4}
    # Same timestamps, reversed arrival: last writer (id-0) wins, proving
    # ties follow arrival order rather than id sort order.
    assert engine.replay_events(list(reversed(base))).state == {"k": 0}
    late = dataclasses.replace(base[0], timestamp=9.0)
    assert engine.replay_events([late] + base[1:]).state == {"k": 0}


def test_ledger_genesis_and_chain():
    ledger = EventLedger()
    e1 = ledger.append(type="E1", payload={}, provenance={})
    assert e1.prev_event_hash is None
    assert ledger.verify_chain() is True
    ledger._events[1:] = []
    e2 = ledger.append(type="E2", payload={}, provenance={})
    assert e2.prev_event_hash is not None
    assert ledger.verify_chain() is True


def test_ledger_detects_tamper():
    ledger = EventLedger()
    ledger.append(type="E1", payload={}, provenance={})
    ledger.append(type="E2", payload={}, provenance={})
    import dataclasses
    ledger._events[1] = dataclasses.replace(ledger._events[1], prev_event_hash="tampered")
    assert ledger.verify_chain() is False


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8])
def test_anchor_delta_storage_scales(n):
    engine = ReplayEngine()
    engine.add_anchor("rev0", {"k0": "v0"})
    prev = "rev0"
    for i in range(1, n + 1):
        engine.add_delta(prev, f"rev{i}", {f"k{i}": "v"})
        prev = f"rev{i}"
    result = engine.replay("rev0", prev)
    assert len(result.state) == n + 1
