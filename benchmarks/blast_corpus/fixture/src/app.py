"""Cross-file callers of hub (C2 fixture). Topology (caller -> callee):
  remote          -> hub   (remote def L8, body L9)
  Gateway.handle  -> hub   (method def L13, body L14)
"""
from src.core import hub


def remote(x):
    return hub(x)


class Gateway:
    def handle(self):
        return hub(2)
