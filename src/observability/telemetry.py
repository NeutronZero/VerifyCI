class Telemetry:
    def __init__(self):
        self._spans = []

    def record_span(self, name: str, attributes: dict):
        self._spans.append({"name": name, "attributes": attributes})

    def get_spans(self) -> list[dict]:
        return list(self._spans)
