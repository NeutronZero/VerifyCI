"""FastMCP daemon endpoint for IDE and agent pair verification."""

from __future__ import annotations

from typing import Any, Mapping

from verifyci.contracts.attestation import VerificationCertificate
from verifyci.contracts.verdict import VerificationVerdict
from verifyci.core.diff_parser import DiffFileEntry
from verifyci.core.engine import VerificationKernel


def handle_verify_request(
    file_path: str,
    base_source: str,
    head_source: str,
    diff_text: str = "",
) -> dict[str, Any]:
    """Execute in-memory verification for MCP daemon requests."""
    entry = DiffFileEntry.from_sources(
        file_path=file_path,
        base_source=base_source,
        head_source=head_source,
        diff=diff_text,
    )

    kernel = VerificationKernel(base_sources={file_path: base_source})
    cert = kernel.verify_entries([entry])

    return {
        "verdict": cert.verdict.value,
        "digest": cert.digest,
        "rationale": cert.rationale,
        "findings": [f.to_dict() for f in cert.payload.findings],
    }
