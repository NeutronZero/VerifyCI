"""Composite component and proximity correlation engine (CAP-002B)."""
from __future__ import annotations

import re
from typing import Sequence

from verifyci.secrets.contracts import (
    DetectionSignal,
    ResourceLimitExceeded,
    SignalCategory,
)

_CONTEXT_MARKERS = re.compile(
    r"""(?i)\b(?:credential|secret|auth|token|service[ _-]?account|private[ _-]?key|api[ _-]?key|password|db_pass)\b"""
)


class CompositeSignalEngine:
    """Discovers and correlates supporting signals across line windows within resource limits."""

    def __init__(
        self,
        line_window: int = 3,
        max_components: int = 50,
        max_combinations: int = 100,
    ):
        self.line_window = line_window
        self.max_components = max_components
        self.max_combinations = max_combinations

    def extract_context_signals(
        self,
        lines: Sequence[tuple[int | None, str]],
    ) -> dict[int, list[DetectionSignal]]:
        """Index context signals by line number."""
        signals_by_line: dict[int, list[DetectionSignal]] = {}
        total_signals = 0

        for lineno, content in lines:
            if lineno is None:
                continue
            for match in _CONTEXT_MARKERS.finditer(content):
                total_signals += 1
                if total_signals > self.max_components:
                    raise ResourceLimitExceeded(
                        f"Component count exceeded limit ({self.max_components})",
                        limit_type="component_count",
                    )
                sig = DetectionSignal(
                    signal_id=f"ctx_{match.group(0).lower()}",
                    category=SignalCategory.CONTEXT,
                    span=match.span(),
                    confidence=0.8,
                    description=f"Nearby credential context marker: {match.group(0)}",
                )
                signals_by_line.setdefault(lineno, []).append(sig)

        return signals_by_line

    def find_supporting_signals(
        self,
        lineno: int | None,
        context_signals: dict[int, list[DetectionSignal]],
    ) -> list[DetectionSignal]:
        """Find context signals within the line window of lineno."""
        if lineno is None:
            return []
        supporting = []
        for line_offset in range(-self.line_window, self.line_window + 1):
            target_line = lineno + line_offset
            if target_line in context_signals:
                supporting.extend(context_signals[target_line])
            if len(supporting) > self.max_combinations:
                raise ResourceLimitExceeded(
                    f"Supporting-signal fan-out exceeded limit ({self.max_combinations})",
                    limit_type="combination_count",
                )
        return supporting
