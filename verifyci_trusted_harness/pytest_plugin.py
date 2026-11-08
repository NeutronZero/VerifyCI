"""Trusted Pytest Plugin for Sandboxed Worker Execution (§15.10 Component D).

Registered explicitly with pytest.main(plugins=[TrustedWorkerPlugin()]).
Provides command-line options and worker invocation fixtures.
"""
from __future__ import annotations

import pytest


class TrustedWorkerPlugin:
    """Plugin explicitly passed to pytest.main() to manage candidate worker invocations."""

    def pytest_addoption(self, parser: pytest.Parser) -> None:
        group = parser.getgroup("verifyci-worker", "VerifyCI candidate worker options")
        group.addoption(
            "--candidate-worker-image",
            action="store",
            default="",
            help="OCI digest of the verified candidate worker image",
        )
        group.addoption(
            "--candidate-staging",
            action="store",
            default="",
            help="Path to clean materialized candidate staging directory",
        )

    def pytest_configure(self, config: pytest.Config) -> None:
        self.worker_image = config.getoption("--candidate-worker-image")
        self.candidate_staging = config.getoption("--candidate-staging")
