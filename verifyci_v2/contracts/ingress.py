"""Ingress rate limiting and per-query budget contracts.

These bound untrusted work entering the engine through any interface (MCP
daemon, CLI, or future transports). They live in `contracts/` rather than
`interface/` because the configuration is part of the engine's public
configuration surface: `VerifyCIConfig` and the daemon both need it, and
placing it here keeps `verifyci_v2/__init__.py` from importing the interface
layer to read a struct of four numbers.
"""

from __future__ import annotations

import time
from typing import Callable

import msgspec


class IngressLimitExceededError(RuntimeError):
    """Raised when a tool call exceeds rate limits, payload bounds, or CPU wall-clock budgets."""


class IngressBudgetConfig(msgspec.Struct, frozen=True, kw_only=True):
    max_payload_bytes: int = 2 * 1024 * 1024  # 2 MiB max payload
    rate_limit_capacity: float = 50.0  # Burst capacity (requests)
    rate_limit_refill_per_sec: float = 25.0  # Token refill rate
    max_query_wall_ms: float = 500.0  # Per-query wall-clock budget


class TokenBucketRateLimiter:
    """Deterministic token-bucket rate limiter protecting the stateful MCP daemon."""

    def __init__(
        self,
        capacity: float = 50.0,
        refill_per_sec: float = 25.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._clock = clock
        self._tokens = capacity
        self._last_timestamp = clock()

    def consume(self, tokens: float = 1.0) -> bool:
        now = self._clock()
        elapsed = max(0.0, now - self._last_timestamp)
        self._last_timestamp = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_sec)
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False