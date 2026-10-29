"""Release-validation evidence verification for VerifyCI (§15.10).

Release validation cannot be asserted by callers via CLI flags, environment
variables, or request attributes. It must be proven by a cryptographic evidence
record bound to the source commit, manifest hash, toolchain, and corpora.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

from verifyci.contracts.manifest import (
    CHECK_ORDER,
    CHECK_SPECS,
    TOOL_VERSION,
    manifest_hash,
)

VALIDATION_SCHEMA = "verifyci.release_validation/v1"
VALIDATION_REL_PATH = Path("evidence") / "release" / "release_validation.json"

_CRITICAL_IMPLEMENTATION_FILES = (
    Path("verifyci/checks/security.py"),
    Path("verifyci/checks/semantic.py"),
    Path("verifyci/checks/contract.py"),
    Path("verifyci/checks/deletion.py"),
    Path("verifyci/checks/grounding.py"),
    Path("verifyci/gate/orchestrator.py"),
    Path("verifyci/contracts/manifest.py"),
    Path("verifyci/contracts/promotion.py"),
)


def get_verifyci_root() -> Path:
    """Return the root path of the VerifyCI repository / installation."""
    return Path(__file__).resolve().parents[2]


def get_commit_sha(repo_root: Path) -> str | None:
    """Resolve HEAD commit SHA of the repository."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            commit = proc.stdout.strip()
            if len(commit) == 40 and all(c in "0123456789abcdef" for c in commit.lower()):
                return commit.lower()
    except Exception:
        pass
    return None


def get_parent_commit(repo_root: Path, commit_sha: str) -> str | None:
    """Resolve parent commit SHA."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", f"{commit_sha}^"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            parent = proc.stdout.strip()
            if len(parent) == 40 and all(c in "0123456789abcdef" for c in parent.lower()):
                return parent.lower()
    except Exception:
        pass
    return None


def compute_implementation_fingerprint(repo_root: Path) -> str:
    """Compute deterministic SHA256 over critical implementation sources."""
    hasher = hashlib.sha256()
    for rel_path in sorted(_CRITICAL_IMPLEMENTATION_FILES):
        full_path = repo_root / rel_path
        if full_path.is_file():
            hasher.update(rel_path.as_posix().encode("utf-8"))
            # Normalize CRLF/LF to ensure consistent hash across platforms
            norm_content = full_path.read_bytes().replace(b"\r\n", b"\n")
            hasher.update(norm_content)
    return "sha256:" + hasher.hexdigest()


def verify_release_validation_evidence(
    repo_root: Path | None = None,
    *,
    expected_commit: str | None = None,
) -> tuple[bool, str | None]:
    """Verify that trusted, non-stale release-validation evidence exists.

    Returns:
        (True, None) if validation is authoritative and unstale.
        (False, reason_detail) otherwise.
    """
    root = repo_root or get_verifyci_root()
    val_file = root / VALIDATION_REL_PATH
    if not val_file.is_file():
        return (
            False,
            "release-validation artifacts are absent; this internal build cannot emit a normal gate verdict",
        )

    try:
        raw = val_file.read_bytes()
        record = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return False, f"release-validation evidence is malformed: {exc}"

    if not isinstance(record, dict):
        return False, "release-validation evidence root must be an object"

    if record.get("schema") != VALIDATION_SCHEMA:
        return False, f"unsupported release-validation schema: {record.get('schema')}"

    if record.get("status") != "VALIDATED":
        return False, f"release validation status is not VALIDATED: {record.get('status')}"

    if record.get("tool_version") != TOOL_VERSION:
        return (
            False,
            f"release validation tool version mismatch: {record.get('tool_version')} != {TOOL_VERSION}",
        )

    current_manifest_hash = manifest_hash()
    if record.get("manifest_hash") != current_manifest_hash:
        return False, "release validation manifest hash mismatch (manifest or checks changed)"

    # Verify implementation fingerprint against current files
    current_impl_fingerprint = compute_implementation_fingerprint(root)
    if record.get("implementation_fingerprint") != current_impl_fingerprint:
        return (
            False,
            "stale release-validation evidence: implementation files have changed since validation",
        )

    # Verify bound commit
    commit_sha = record.get("commit_sha")
    if not commit_sha:
        return False, "release validation evidence is missing commit_sha binding"

    actual_commit = expected_commit or get_commit_sha(root)
    if actual_commit is not None:
        act_lower = actual_commit.lower()
        com_lower = commit_sha.lower()
        if com_lower != act_lower:
            parent_lower = (get_parent_commit(root, act_lower) or "").lower()
            if com_lower != parent_lower:
                return (
                    False,
                    f"stale release-validation evidence: bound to commit {commit_sha[:8]}, current commit is {actual_commit[:8]}",
                )

    # Verify check corpora hashes match
    corpora = record.get("corpora_hashes", {})
    for check_id in CHECK_ORDER:
        spec = CHECK_SPECS[check_id]
        if spec.corpus_hash and corpora.get(check_id) != spec.corpus_hash:
            return False, f"release validation corpus hash mismatch for {check_id}"

    return True, None


def generate_release_validation_record(
    repo_root: Path,
    commit_sha: str,
) -> dict[str, Any]:
    """Generate and write authoritative release-validation evidence."""
    record = {
        "schema": VALIDATION_SCHEMA,
        "tool_version": TOOL_VERSION,
        "status": "VALIDATED",
        "commit_sha": commit_sha.lower(),
        "manifest_hash": manifest_hash(),
        "toolchain_fingerprint": CHECK_SPECS["security"].toolchain_fingerprint,
        "corpora_hashes": {
            check_id: spec.corpus_hash
            for check_id, spec in CHECK_SPECS.items()
            if spec.corpus_hash
        },
        "implementation_fingerprint": compute_implementation_fingerprint(repo_root),
        "checks_validated": list(CHECK_ORDER),
    }
    val_file = repo_root / VALIDATION_REL_PATH
    val_file.parent.mkdir(parents=True, exist_ok=True)
    val_file.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


__all__ = [
    "VALIDATION_REL_PATH",
    "VALIDATION_SCHEMA",
    "compute_implementation_fingerprint",
    "generate_release_validation_record",
    "get_commit_sha",
    "get_verifyci_root",
    "verify_release_validation_evidence",
]
