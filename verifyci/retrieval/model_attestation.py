"""Runtime model attestation for VerifyCI retrieval components.

Validates local model artifacts (HuggingFace snapshot commits, weights,
and composite file hashes) fail-closed without network access.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def compute_snapshot_manifest(
    snap_path: Path,
) -> tuple[str, dict[str, str], list[dict[str, Any]]]:
    """Compute canonical snapshot manifest and composite SHA-256 digest.

    Enumerates all files recursively, sorted by normalized relative POSIX path.
    Builds a canonical manifest of per-file records:
      - path: relative POSIX path
      - sha256: file SHA-256 hex digest
      - size_bytes: file size in bytes
    Serializes the manifest deterministically (canonical JSON) and computes
    the composite SHA-256 over that serialization.

    Returns:
        (composite_sha256, files_dict, manifest_list)
    """
    raw_files = [x for x in snap_path.rglob("*") if x.is_file()]
    file_paths = sorted(raw_files, key=lambda x: x.relative_to(snap_path).as_posix())
    if not file_paths:
        raise ValueError(f"Snapshot directory {snap_path} contains no files.")

    files: dict[str, str] = {}
    manifest: list[dict[str, Any]] = []
    for p in file_paths:
        rel_name = p.relative_to(snap_path).as_posix()
        data = p.read_bytes()
        file_sha = hashlib.sha256(data).hexdigest()
        files[rel_name] = file_sha
        manifest.append({
            "path": rel_name,
            "sha256": file_sha,
            "size_bytes": len(data),
        })

    canonical_manifest_bytes = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    composite_sha256 = hashlib.sha256(canonical_manifest_bytes).hexdigest()
    return composite_sha256, files, manifest


def verify_runtime_model(
    model_name_or_path: str,
    expected_snapshot_commit: str | None = None,
    expected_snapshot_sha256: str | None = None,
    require_pin: bool = False,
) -> tuple[bool, dict[str, Any]]:
    """Resolve and verify local cached model artifacts without network access.

    Consistent with `_model_provenance()` in `benchmarks/beir/rerank_measure.py`.
    Fails closed if the model directory cannot be resolved locally, if expected
    snapshot constraints are violated, or if require_pin is enabled without a pin.

    Returns:
        (True, details) on success, or (False, details_with_error) on failure.
    """
    model_str = str(model_name_or_path).strip() if model_name_or_path is not None else ""
    if require_pin and not expected_snapshot_sha256:
        return False, {
            "model": model_str,
            "verified": False,
            "error": "Enforced model attestation requires a trusted expected_snapshot_sha256 pin.",
        }

    if not model_str:
        return False, {
            "model": str(model_name_or_path),
            "verified": False,
            "error": "Model name or path is empty or invalid.",
        }

    snap_path: Path | None = None
    direct_path = Path(model_str)
    if direct_path.is_dir():
        snap_path = direct_path.resolve()
    elif direct_path.exists() and not direct_path.is_dir():
        return False, {
            "model": model_str,
            "verified": False,
            "error": f"Model path {model_str!r} exists but is not a directory.",
        }
    else:
        try:
            from huggingface_hub import snapshot_download  # type: ignore

            resolved = snapshot_download(model_str, local_files_only=True)
            candidate = Path(resolved)
            if candidate.is_dir():
                snap_path = candidate.resolve()
            else:
                return False, {
                    "model": model_str,
                    "verified": False,
                    "error": f"Resolved path for {model_str!r} is not a directory: {resolved}",
                }
        except Exception as exc:
            return False, {
                "model": model_str,
                "verified": False,
                "error": f"Failed to resolve local model snapshot for {model_str!r}: {exc}",
            }

    if snap_path is None or not snap_path.is_dir():
        return False, {
            "model": model_str,
            "verified": False,
            "error": f"Model directory {model_str!r} could not be resolved locally.",
        }

    try:
        raw_files = [x for x in snap_path.rglob("*") if x.is_file()]
        if not raw_files:
            return False, {
                "model": model_str,
                "snapshot_path": str(snap_path),
                "verified": False,
                "error": f"Model snapshot directory {snap_path} contains no files.",
            }

        snapshot_sha256, files, manifest = compute_snapshot_manifest(snap_path)
        snapshot_commit = snap_path.name
    except Exception as exc:
        return False, {
            "model": model_str,
            "snapshot_path": str(snap_path),
            "verified": False,
            "error": f"Failed reading model snapshot files from {snap_path}: {exc}",
        }

    details: dict[str, Any] = {
        "model": model_str,
        "snapshot_path": str(snap_path),
        "snapshot_commit": snapshot_commit,
        "snapshot_sha256": snapshot_sha256,
        "files": files,
        "manifest": manifest,
        "verified": True,
    }

    errors: list[str] = []
    if expected_snapshot_commit is not None:
        details["expected_snapshot_commit"] = expected_snapshot_commit
        if snapshot_commit != expected_snapshot_commit:
            errors.append(
                f"Snapshot commit mismatch: expected {expected_snapshot_commit!r}, got {snapshot_commit!r}"
            )

    if expected_snapshot_sha256 is not None:
        details["expected_snapshot_sha256"] = expected_snapshot_sha256
        if snapshot_sha256 != expected_snapshot_sha256:
            errors.append(
                f"Snapshot SHA-256 mismatch: expected {expected_snapshot_sha256!r}, got {snapshot_sha256!r}"
            )

    if errors:
        details["verified"] = False
        details["error"] = "; ".join(errors)
        return False, details

    return True, details
