
import copy

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
            state=copy.deepcopy(state),
            timestamp=time.time(),
        )

    def add_delta(self, from_revision: str, to_revision: str, delta: dict):
        self._deltas.append((from_revision, to_revision, copy.deepcopy(delta)))

    def replay(self, from_revision: str, to_revision: str) -> ProjectionState:
        import time

        anchor = self._anchors.get(from_revision)
        substituted = False
        if anchor is None:
            # Documented fallback (see get_latest_anchor): replay from the
            # latest stored anchor when the requested one is absent. The
            # result is LABELED with the anchor actually used, never with
            # the requested revision — state derived from the wrong base
            # must not masquerade as a correct replay.
            anchor = self.get_latest_anchor(from_revision)
            substituted = anchor is not None and anchor.revision_id != from_revision
        if anchor is None:
            raise RuntimeError(
                f"no anchor for replay {from_revision!r} -> {to_revision!r}")

        state = copy.deepcopy(anchor.state)
        current = anchor.revision_id  # resume from the anchor actually used

        from collections import deque
        queue = deque([(current, [])])
        seen = {current}
        path_deltas = None
        while queue:
            node, path = queue.popleft()
            if node == to_revision:
                path_deltas = path
                break
            for f_rev, t_rev, delta in self._deltas:
                if f_rev == node and t_rev not in seen:
                    seen.add(t_rev)
                    queue.append((t_rev, path + [delta]))

        if path_deltas is not None:
            for delta in path_deltas:
                state.update(copy.deepcopy(delta))
            current = to_revision
        else:
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
                state.update(copy.deepcopy(delta))

        if current != to_revision:
            # Fail closed: a partial state labeled with an unreached
            # revision would verify against history that never happened.
            raise RuntimeError(
                f"no delta path for replay {from_revision!r} ->"
                f" {to_revision!r} (reached {current!r})")

        base = anchor.revision_id
        projection_id = f"replay_{base}_{to_revision}"
        if substituted:
            projection_id += f"~substituted_for_{from_revision}"
        return ProjectionState(
            projection_id=projection_id,
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
        """Event-sourced replay: fold event payloads into projection state.

        P3: folded in timestamp order so out-of-order delivery cannot
        silently produce a non-equivalent state; nested payload values are
        deep-copied so the projection never aliases ledger-owned objects.
        The sort is STABLE with no id tiebreak: on coarse clocks (Windows
        ~15ms granularity) many events share one timestamp, and ids are
        random uuids — tiebreaking by id would scramble insertion order.
        Equal timestamps therefore keep arrival order. Last-write-wins
        per key remains the documented merge rule.
        """
        import copy
        import time

        def _order_key(event):
            return getattr(event, "timestamp", 0.0) or 0.0

        state: dict = {}
        revision_id = ""
        for event in sorted(events, key=_order_key):
            payload = getattr(event, "payload", {}) or {}
            if isinstance(payload, dict):
                state.update({k: copy.deepcopy(v) for k, v in payload.items()
                              if k != "task_id"})
            revision_id = getattr(event, "id", revision_id) or revision_id
        return ProjectionState(
            projection_id=f"replay_events_{len(events)}",
            revision_id=revision_id,
            state=state,
            timestamp=time.time(),
        )
