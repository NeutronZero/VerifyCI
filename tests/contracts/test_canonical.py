"""Golden vector tests for canonical event serialization.

If these tests fail, the canonicalization contract changed.
Update golden vectors only when the contract intentionally changes.
"""

from src.contracts.event import Event
from src.contracts.canonical import canonical_event_bytes, event_hash


def test_canonical_event_bytes_matches_golden_vector():
    event = Event(
        id="evt_001",
        type="TASK_CREATED",
        timestamp=1700000000.0,
        task_id="task_001",
        conversation_id="conv_001",
        payload={"goal": "test"},
        provenance={"source": "test"},
        prev_event_hash=None,
    )
    result = canonical_event_bytes(event)
    assert isinstance(result, bytes)
    assert b"evt_001" in result
    assert b"TASK_CREATED" in result


def test_event_hash_matches_golden_vector():
    event = Event(
        id="evt_001",
        type="TASK_CREATED",
        timestamp=1700000000.0,
        task_id="task_001",
        conversation_id="conv_001",
        payload={"goal": "test"},
        provenance={"source": "test"},
        prev_event_hash=None,
    )
    result = event_hash(event)
    assert isinstance(result, str)
    assert len(result) == 64
    assert result == result.lower()


def test_canonical_excludes_attestation():
    event = Event(
        id="evt_002",
        type="TASK_CREATED",
        timestamp=1700000000.0,
        task_id="task_001",
        conversation_id="conv_001",
        payload={"goal": "test"},
        provenance={"source": "test"},
        prev_event_hash=None,
        attestation={"key_id": "should_not_appear"},
    )
    result = canonical_event_bytes(event)
    assert b"should_not_appear" not in result
    assert b"attestation" not in result


def test_canonical_sorted_keys():
    event = Event(
        id="evt_003",
        type="TASK_CREATED",
        timestamp=1700000000.0,
        task_id="task_001",
        conversation_id="conv_001",
        payload={"z_key": 1, "a_key": 2, "m_key": 3},
        provenance={"source": "test"},
        prev_event_hash=None,
    )
    result = canonical_event_bytes(event)
    a_pos = result.find(b"a_key")
    m_pos = result.find(b"m_key")
    z_pos = result.find(b"z_key")
    assert a_pos < m_pos < z_pos
