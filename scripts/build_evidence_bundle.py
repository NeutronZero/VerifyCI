#!/usr/bin/env python3
"""Builds and anchors the canonical evidence bundle for VerifyCI v2.0."""
from __future__ import annotations

import json
from pathlib import Path

from verifyci_v2.interface.cap_adjudicator import V2CapabilityAdjudicator


def main() -> int:
    evidence_dir = Path("evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = evidence_dir / "evidence-bundle.json"

    adjudicator = V2CapabilityAdjudicator()
    results = adjudicator.run_self_test_smoke_suite()

    bundle_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Evidence bundle written to {bundle_path} ({results['passed_count']}/{results['total_capabilities']} gates passed)")
    return 0 if results["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
