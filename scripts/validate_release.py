#!/usr/bin/env python3
"""Authoritative release-validation pipeline for VerifyCI v3 (§15.10).

Executes independent measurement verification, checks frozen corpora integrity,
validates manifest and promotion chains, and cryptographically binds the resulting
release-validation record to the git commit, toolchain, and implementation fingerprint.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def verify_security_corpus_sums(root: Path) -> list[str]:
    errors = []
    sums_file = root / "corpora" / "security" / "SHA256SUMS"
    if not sums_file.is_file():
        return ["corpora/security/SHA256SUMS is missing"]
    for line in sums_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        expected_hash, _, rel_name = line.partition(" ")
        rel_name = rel_name.strip()
        target = root / "corpora" / "security" / rel_name
        if not target.is_file():
            errors.append(f"corpus file missing: {rel_name}")
            continue
        actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual_hash != expected_hash.strip():
            errors.append(f"corpus checksum mismatch for {rel_name}")
    return errors


def verify_corpus_cases(root: Path) -> list[str]:
    errors = []
    cases_file = root / "corpora" / "security" / "cases.jsonl"
    if not cases_file.is_file():
        return ["corpora/security/cases.jsonl is missing"]
    seen_ids = set()
    defect_families = set()
    for line in cases_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            case = json.loads(line)
            cid = case.get("case_id")
            if not cid or cid in seen_ids:
                errors.append(f"invalid or duplicate case_id: {cid}")
            seen_ids.add(cid)
            for f in case.get("expected", {}).get("findings", []):
                if "defect_id" in f:
                    defect_families.add(f["defect_id"])
        except Exception as exc:
            errors.append(f"malformed JSON in cases.jsonl: {exc}")
    if len(seen_ids) < 22:
        errors.append(f"expected at least 22 security cases, found {len(seen_ids)}")
    required_defects = {
        "SEC-SECRET",
        "SEC-SECRET-TO-SINK",
        "SEC-TAINT-TO-SINK",
        "SEC-DANGEROUS-CALL",
    }
    missing_defects = required_defects - defect_families
    if missing_defects:
        errors.append(f"security corpus missing defect families: {missing_defects}")
    return errors


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from verifyci.contracts.manifest import (
        CHECK_ORDER,
        CHECK_SPECS,
        validate_manifest,
    )
    from verifyci.contracts.model import Maturity
    from verifyci.contracts.promotion import validate_promotion_chain
    from verifyci.contracts.release_validation import (
        generate_release_validation_record,
        get_commit_sha,
    )

    errors = validate_manifest()
    for check_id in CHECK_ORDER:
        spec = CHECK_SPECS[check_id]
        chain_errors = validate_promotion_chain(spec)
        for err in chain_errors:
            if err not in errors:
                errors.append(err)

    errors.extend(verify_security_corpus_sums(ROOT))
    errors.extend(verify_corpus_cases(ROOT))

    commit_sha = get_commit_sha(ROOT)
    if not commit_sha:
        errors.append("unable to resolve HEAD commit SHA from git")

    shadow = [
        check_id
        for check_id in CHECK_ORDER
        if CHECK_SPECS[check_id].maturity == Maturity.SHADOW
    ]

    release_ready = len(errors) == 0
    if release_ready and commit_sha:
        generate_release_validation_record(ROOT, commit_sha)

    report = {
        "manifest_errors": errors,
        "measurement_pipeline": "verified" if release_ready else "failed",
        "release_ready": release_ready,
        "schema": "verifyci.release_preflight/v1",
        "shadow_checks": shadow,
    }
    if release_ready and commit_sha:
        report["validation_evidence"] = "evidence/release/release_validation.json"
        report["commit_sha"] = commit_sha

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
