class Metrics:
    def __init__(self):
        self._counters = {}

    def increment(self, name: str, value: int = 1):
        self._counters[name] = self._counters.get(name, 0) + value

    def get(self, name: str) -> int:
        return self._counters.get(name, 0)
