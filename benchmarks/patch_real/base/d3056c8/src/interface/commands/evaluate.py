from src.memory.ledger import EventLedger
from src.memory.replay import ReplayEngine
from src.verification.intent_align import evaluate_invariants


def run_evaluate() -> dict:
    ledger = EventLedger()
    ledger.append(type="TASK_CREATED", payload={"goal": "eval"}, provenance={"source": "evaluate"})
    ledger.append(type="TOOL_CALLED", payload={"outcome": "ok"}, provenance={"source": "evaluate"})
    chain_ok = ledger.verify_chain()

    engine = ReplayEngine()
    engine.add_anchor("rev1", {"a": 1})
    engine.add_delta("rev1", "rev2", {"b": 2})
    replay_ok = engine.replay("rev1", "rev2").state == {"a": 1, "b": 2}
    events_ok = engine.replay_events(ledger.get_events()).state.get("goal") == "eval"

    _, metrics = evaluate_invariants("diff", [], None)
    return {
        "ledger_chain": chain_ok,
        "replay_equivalence": replay_ok,
        "event_replay": events_ok,
        "invariant_metrics": {
            "check_coverage": metrics.check_coverage,
            "detection_recall": metrics.detection_recall,
            "detection_precision": metrics.detection_precision,
        },
    }
