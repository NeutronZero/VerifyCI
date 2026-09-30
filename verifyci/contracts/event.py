from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class AttestationMetadata:
    key_id: str
    signature_algorithm: str
    public_key_id: str
    signed_at: float
    signature: str
    signed_hash: str


@dataclass(frozen=True)
class Event:
    id: str
    type: str
    timestamp: float
    task_id: Optional[str] = None
    conversation_id: Optional[str] = None
    payload: Optional[dict[str, Any]] = None
    provenance: Optional[dict[str, Any]] = None
    prev_event_hash: Optional[str] = None
    attestation: Optional[AttestationMetadata] = None

    def __post_init__(self):
        if self.payload is None:
            object.__setattr__(self, 'payload', {})
        if self.provenance is None:
            object.__setattr__(self, 'provenance', {})
