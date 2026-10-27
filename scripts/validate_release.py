#!/usr/bin/env python3
"""Fail-closed preflight for VerifyCI v3 promotion evidence.

This command validates the checked-in manifest and any promotion chains. It is not
the measurement pipeline described by §15.10 and cannot create release evidence;
release remains blocked until that independent pipeline and its inputs exist.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from verifyci.contracts.manifest import CHECK_ORDER, CHECK_SPECS, validate_manifest
    from verifyci.contracts.model import Maturity

    errors = validate_manifest()
    shadow = [
        check_id
        for check_id in CHECK_ORDER
        if CHECK_SPECS[check_id].maturity == Maturity.SHADOW
    ]
    report = {
        "schema": "verifyci.release_preflight/v1",
        "release_ready": False,
        "manifest_errors": errors,
        "shadow_checks": shadow,
        "measurement_pipeline": "not_implemented",
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    print(
        "Release blocked: the §15.10 measurement pipeline is not implemented; "
        "any shadow checks also require independent evidence and promotion records.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
