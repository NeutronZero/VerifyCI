"""Measure cap011 against the frozen corpus using the VerifyCI v2 engine.

v1 drove this capability through `verifyci.*` modules that no longer exist;
the original harness is preserved in git history. The measurement itself lives
in `benchmarks/common/measure_v2.py` and is shared across capabilities so the
per-capability scripts cannot drift apart.

Exit codes: 0 pass, 1 fail, 2 not measurable against frozen ground truth.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.common.measure_v2 import main

if __name__ == "__main__":
    raise SystemExit(main("cap011"))
