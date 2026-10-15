"""Compatibility shim re-exporting the v2 redaction engine.

The v1.x surface lived at `verifyci/secrets/redaction.py`; v2 keeps the
single implementation in `verifyci_v2/symbolic/redaction.py` and re-exposes
it here so existing callers and documentation keep resolving.
"""

from verifyci_v2.symbolic.redaction import *  # noqa: F401,F403
from verifyci_v2.symbolic.redaction import (  # noqa: F401
    RedactionResult,
    redact_in_place_mapping,
    redact_secrets,
)
