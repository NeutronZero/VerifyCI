#!/usr/bin/env python3
"""Authoritative Pytest Bootstrap for Supervisor Execution (§15.10 Component D).

Invokes pytest in isolated Python mode (-I) with explicitly loaded trusted plugins.
Prevents candidate-controlled conftest.py, pytest.ini, or third-party plugin discovery.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys

# 1. Scrub runner environment
for var in list(os.environ.keys()):
    if var.startswith(("PYTEST_", "PYTHON")):
        os.environ.pop(var, None)
os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"

if len(sys.argv) < 4:
    sys.exit("usage: run_trusted_tests.py <trusted-root> <worker-image-digest> <candidate-staging> [pytest-args...]")

trusted_root = Path(sys.argv[1]).resolve()
worker_image = sys.argv[2]
candidate_staging = sys.argv[3]
extra_args = sys.argv[4:]

# 2. Resolve and insert trusted-root at head of sys.path
if str(trusted_root) in sys.path:
    sys.path.remove(str(trusted_root))
sys.path.insert(0, str(trusted_root))

from verifyci_trusted_harness.pytest_plugin import TrustedWorkerPlugin  # noqa: E402
import pytest  # noqa: E402

pytest_args = [
    "-c", str(trusted_root / "pytest_trusted.ini") if (trusted_root / "pytest_trusted.ini").is_file() else os.devnull,
    "--confcutdir", str(trusted_root / "tests"),
    "--import-mode=importlib",
    f"--candidate-worker-image={worker_image}",
    f"--candidate-staging={candidate_staging}",
    "-q", "--tb=short",
    "-m", "not benchmark and not performance and not requires_release_evidence",
    str(trusted_root / "tests" / "v3"),
    *extra_args,
]

sys.exit(pytest.main(pytest_args, plugins=[TrustedWorkerPlugin()]))
