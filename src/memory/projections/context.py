from typing import Any

from src.contracts.event import Event


class ContextProjection:
    def __init__(self):
        self.context_items = []

    def project(self, events: list[Event]) -> dict[str, Any]:
        for event in events:
            if event.type in ("DECISION_MADE", "RETRIEVAL_PERFORMED", "VERIFICATION_COMPLETED"):
                self.context_items.append({
                    "type": event.type,
                    "payload": event.payload,
                    "timestamp": event.timestamp,
                })
        return {"context_items": self.context_items}
