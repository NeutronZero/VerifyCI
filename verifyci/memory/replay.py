
from verifyci.contracts.memory_types import ProjectionState


class ReplayEngine:
    def __init__(self):
        self._anchors = {}
        self._deltas = []

    def add_anchor(self, revision_id: str, state: dict):
        import time
        self._anchors[revision_id] = ProjectionState(
            projection_id=f"anchor_{revision_id}",
            revision_id=revision_id,
            state=state,
            timestamp=time.time(),
        )

    def add_delta(self, from_revision: str, to_revision: str, delta: dict):
        self._deltas.append((from_revision, to_revision, delta))

    def replay(self, from_revision: str, to_revision: str) -> ProjectionState:
        import time

        anchor = self._anchors.get(from_revision)
        if anchor is None:
            nearest = self.get_latest_anchor(from_revision)
            anchor = nearest
        if anchor is None:
            return ProjectionState(
                projection_id=f"replay_{from_revision}_{to_revision}",
                revision_id=to_revision,
                state={},
                timestamp=time.time(),
            )

        state = dict(anchor.state)
        current = anchor.revision_id  # resume from the anchor actually used
        visited = set()

        while current != to_revision and current not in visited:
            visited.add(current)
            next_delta = None
            for from_rev, to_rev, delta in self._deltas:
                if from_rev == current:
                    next_delta = (to_rev, delta)
                    break
            if next_delta is None:
                break
            current, delta = next_delta
            state.update(delta)

        return ProjectionState(
            projection_id=f"replay_{from_revision}_{to_revision}",
            revision_id=to_revision,
            state=state,
            timestamp=time.time(),
        )

    def get_latest_anchor(self, revision_id: str):
        """Latest stored anchor (insertion order), used when no anchor
        exists for the requested revision. Named for what it is: this is
        recency, not revision proximity — replay then walks forward from
        whatever the anchor actually holds (see `current` reassignment).
        """
        if revision_id in self._anchors:
            return self._anchors[revision_id]
        anchors = list(self._anchors.values())
        return anchors[-1] if anchors else None

    def replay_events(self, events) -> ProjectionState:
        """Event-sourced replay: fold event payloads into projection state."""
        import time

        state: dict = {}
        revision_id = ""
        for event in events:
            payload = getattr(event, "payload", {}) or {}
            if isinstance(payload, dict):
                state.update({k: v for k, v in payload.items() if k != "task_id"})
            revision_id = getattr(event, "id", revision_id) or revision_id
        return ProjectionState(
            projection_id=f"replay_events_{len(events)}",
            revision_id=revision_id,
            state=state,
            timestamp=time.time(),
        )
