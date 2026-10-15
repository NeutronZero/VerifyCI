"""Spec-compatibility shim: implements verifyci/secrets/redaction.py from v1.x."""

from verifyci_v2.symbolic.redaction import (  # noqa: F401
    RedactionResult,
    redact_in_place_mapping,
    redact_secrets,
)

__all__ = ["RedactionResult", "redact_secrets", "redact_in_place_mapping"]
