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
    from verifyci.contracts.manifest import (
        CHECK_ORDER,
        CHECK_SPECS,
        RELEASE_VALIDATED,
        validate_manifest,
    )
    from verifyci.contracts.model import Maturity
    from verifyci.contracts.promotion import validate_promotion_chain

    errors = validate_manifest()
    for check_id in CHECK_ORDER:
        spec = CHECK_SPECS[check_id]
        chain_errors = validate_promotion_chain(spec)
        for err in chain_errors:
            if err not in errors:
                errors.append(err)

    if not RELEASE_VALIDATED:
        errors.append("RELEASE_VALIDATED is False in manifest contract")

    shadow = [
        check_id
        for check_id in CHECK_ORDER
        if CHECK_SPECS[check_id].maturity == Maturity.SHADOW
    ]

    release_ready = len(errors) == 0 and RELEASE_VALIDATED
    report = {
        "manifest_errors": errors,
        "measurement_pipeline": "verified" if release_ready else "not_implemented",
        "release_ready": release_ready,
        "schema": "verifyci.release_preflight/v1",
        "shadow_checks": shadow,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    if not release_ready:
        print(
            "Release blocked: the §15.10 measurement pipeline or promotion records failed validation.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
