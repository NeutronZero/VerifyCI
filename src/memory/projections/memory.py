from src.contracts.event import Event


class MemoryProjection:
    def __init__(self):
        self.decisions = []
        self.lessons = []
        self.preferences = []

    def project(self, events: list[Event]) -> dict:
        for event in events:
            if event.type == "DECISION_MADE":
                self.decisions.append(event.payload)
            elif event.type == "TOOL_CALLED" and event.payload.get("outcome") == "failure":
                self.lessons.append(event.payload)
        return {
            "decisions": self.decisions,
            "lessons": self.lessons,
            "preferences": self.preferences,
        }
