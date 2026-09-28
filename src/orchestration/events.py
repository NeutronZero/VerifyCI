from src.memory.ledger import EventLedger


def emit_event(ledger: EventLedger, type: str, payload: dict, provenance: dict):
    return ledger.append(type=type, payload=payload, provenance=provenance)
