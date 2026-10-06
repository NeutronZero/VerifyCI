"""Contracts and data models for VerifyCI clean-room secret detection (CAP-002B)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class SignalCategory(str, Enum):
    PATTERN = "pattern"
    ENTROPY = "entropy"
    STRUCTURE = "structure"
    CONTEXT = "context"
    DECODED = "decoded"


@dataclass(frozen=True)
class DetectionSignal:
    signal_id: str
    category: SignalCategory
    span: tuple[int, int]
    confidence: float
    description: str


@dataclass(frozen=True)
class TransformTrace:
    transform_type: str
    depth: int
    original_span: tuple[int, int]
    source_hash: str
    description: str


@dataclass(frozen=True)
class SuppressionDecision:
    suppressed: bool
    reason: str
    rule_id: str
    scope: str = "global"
    superseded_by_rule_id: Optional[str] = None


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    detector_family: str
    file_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    col_start: Optional[int]
    col_end: Optional[int]
    finding_fingerprint: str
    source_hash: str
    redacted_value: str
    redacted_context: str
    signals: tuple[DetectionSignal, ...]
    transforms: tuple[TransformTrace, ...]
    suppression: Optional[SuppressionDecision]
    rule_config_hash: str
    confidence: float

    @property
    def is_active(self) -> bool:
        """True if candidate was not suppressed."""
        return self.suppression is None or not self.suppression.suppressed

    def evidence_string(self) -> str:
        """Deterministic evidence representation for VerifyCI IR."""
        line = self.line_start if self.line_start is not None else "?"
        return f"{self.file_path}:{line}:{self.rule_id}"


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    description: str
    detector_family: str
    pattern_strategy: Any  # compiled regex, callable, or custom detector
    keywords: tuple[str, ...] = ()
    path_patterns: tuple[str, ...] = ()
    excluded_path_patterns: tuple[str, ...] = ()
    confidence: float = 0.95
    specificity: int = 50
    supporting_signals: tuple[str, ...] = ()
    entropy_threshold: Optional[float] = None
    min_length: int = 6
    max_length: int = 4096
    requires_supporting_context: bool = False


@dataclass
class DetectorContext:
    file_path: str = "unscoped"
    max_decode_depth: int = 2
    max_candidates: int = 1000
    max_component_combinations: int = 100
    timeout_seconds: float = 10.0
    start_time: float = field(default_factory=time.time)
    test_allowlist_patterns: tuple[str, ...] = ()

    def is_timeout(self) -> bool:
        return (time.time() - self.start_time) > self.timeout_seconds


class ResourceLimitExceeded(RuntimeError):
    """Raised when fragment size, candidate count, or timeout limit is exceeded."""
    def __init__(self, message: str, limit_type: str):
        super().__init__(message)
        self.limit_type = limit_type
