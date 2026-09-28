from typing import Any

from src.contracts.event import Event


class KnowledgeProjection:
    def __init__(self):
        self.invariants = []
        self.architecture_rules = []

    def project(self, events: list[Event]) -> dict[str, Any]:
        for event in events:
            if event.type == "PLAN_CREATED":
                if "invariants" in event.payload:
                    self.invariants.extend(event.payload["invariants"])
        return {
            "invariants": self.invariants,
            "architecture_rules": self.architecture_rules,
        }
