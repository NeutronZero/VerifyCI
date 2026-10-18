"""VerifyCI interface endpoints (CLI, SARIF exporter, FastMCP daemon)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from verifyci.interface.cli import main, run_verify_diff
    from verifyci.interface.fastmcp_daemon import handle_verify_request
    from verifyci.interface.sarif_exporter import certificate_to_sarif

__all__ = [
    "certificate_to_sarif",
    "handle_verify_request",
    "main",
    "run_verify_diff",
]


def __getattr__(name: str):
    if name in ("main", "run_verify_diff"):
        from verifyci.interface.cli import main, run_verify_diff
        return main if name == "main" else run_verify_diff
    if name == "handle_verify_request":
        from verifyci.interface.fastmcp_daemon import handle_verify_request
        return handle_verify_request
    if name == "certificate_to_sarif":
        from verifyci.interface.sarif_exporter import certificate_to_sarif
        return certificate_to_sarif
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

