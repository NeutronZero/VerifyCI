"""Core verification engine, diff parser, provenance, and security rules."""

from __future__ import annotations

from verifyci.core.canonical import (
    canonical_json_dumps,
    content_digest_hex,
    redact_secrets,
    redact_token,
)
from verifyci.core.diff_parser import (
    DiffFileEntry,
    RemovedLine,
    parse_unified_diff,
)
from verifyci.core.engine import (
    VerificationKernel,
    parseable_source,
    repair_empty_bodies,
)
from verifyci.core.imports import (
    check_unresolved_imports,
    find_unresolvable_imports,
)
from verifyci.core.provenance import verify_removal_provenance
from verifyci.core.secrets import (
    is_placeholder,
    scan_secrets_in_source,
    shannon_entropy,
)
from verifyci.core.security import is_test_path, scan_dangerous_calls

__all__ = [
    "DiffFileEntry",
    "RemovedLine",
    "VerificationKernel",
    "canonical_json_dumps",
    "check_unresolved_imports",
    "content_digest_hex",
    "find_unresolvable_imports",
    "is_placeholder",
    "is_test_path",
    "parse_unified_diff",
    "parseable_source",
    "redact_secrets",
    "redact_token",
    "repair_empty_bodies",
    "scan_dangerous_calls",
    "scan_secrets_in_source",
    "shannon_entropy",
    "verify_removal_provenance",
]
