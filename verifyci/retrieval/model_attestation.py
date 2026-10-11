"""Runtime model attestation for VerifyCI retrieval components.

Validates local model artifacts (HuggingFace snapshot commits, weights,
and composite file hashes) fail-closed without network access.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def verify_runtime_model(
    model_name_or_path: str,
    expected_snapshot_commit: str | None = None,
    expected_snapshot_sha256: str | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Resolve and verify local cached model artifacts without network access.

    Consistent with `_model_provenance()` in `benchmarks/beir/rerank_measure.py`.
    Fails closed if the model directory cannot be resolved locally or if any
    expected snapshot constraint (commit or SHA-256) is violated.

    Returns:
        (True, details) on success, or (False, details_with_error) on failure.
    """
    model_str = str(model_name_or_path).strip() if model_name_or_path is not None else ""
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
        file_paths = sorted([x for x in snap_path.iterdir() if x.is_file()], key=lambda x: x.name)
        if not file_paths:
            return False, {
                "model": model_str,
                "snapshot_path": str(snap_path),
                "verified": False,
                "error": f"Model snapshot directory {snap_path} contains no files.",
            }

        h = hashlib.sha256()
        files: dict[str, str] = {}
        for p in file_paths:
            data = p.read_bytes()
            files[p.name] = hashlib.sha256(data).hexdigest()
            h.update(p.name.encode("utf-8") + b"\x00" + data)
        snapshot_sha256 = h.hexdigest()
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
