#!/usr/bin/env python3
"""Builds and anchors the canonical RFC 8785 evidence bundle for VerifyCI v3.1."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def main() -> int:
    evidence_dir = Path("evidence")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = evidence_dir / "evidence-bundle.json"

    # Run the v3 test suite first to ensure gate integrity
    test_proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/v3/", "-q"],
        capture_output=True,
        text=True,
    )
    if test_proc.returncode != 0:
        print("Tests failed:\n", test_proc.stderr or test_proc.stdout)
        return test_proc.returncode

    # Build M0 candidate evidence payload using canonical JCS
    from verifyci.contracts.manifest import manifest_hash, manifest_payload
    from verifyci.evidence.canonical import canonical_json_bytes

    manifest = manifest_payload()
    evidence_data = {
        "milestone": "M0",
        "schema": "verifyci.evidence/v3.1",
        "manifest": manifest,
        "manifest_hash": manifest_hash(),
        "status": "PASS",
    }
    bundle_path.write_bytes(canonical_json_bytes(evidence_data))
    print(f"Evidence bundle written to {bundle_path} (manifest {manifest_hash()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
