import time
from typing import Optional

from verifyci.contracts.memory_types import ProjectionState


class SnapshotStore:
    def __init__(self, snapshot_threshold: int = 100):
        self._snapshots = {}
        self._threshold = snapshot_threshold
        self._event_count = 0

    def maybe_snapshot(self, revision_id: str, state: dict) -> Optional[ProjectionState]:
        self._event_count += 1
        if self._event_count >= self._threshold:
            snapshot = ProjectionState(
                projection_id=f"snapshot_{revision_id}",
                revision_id=revision_id,
                state=dict(state),
                timestamp=time.time(),
            )
            self._snapshots[revision_id] = snapshot
            self._event_count = 0
            return snapshot
        return None

    def get_nearest_anchor(self, revision_id: str) -> Optional[ProjectionState]:
        return self._snapshots.get(revision_id)
