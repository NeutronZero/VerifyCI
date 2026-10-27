"""Promotion-record verification for the v3 release evidence chain (§15.10)."""

from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
from typing import Any

from verifyci.contracts.model import Maturity


REPORT_SCHEMA = "verifyci.release_report/v1"
PROMOTION_SCHEMA = "verifyci.promotion_record/v1"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024

_REQUIRED_REQUIREMENTS = frozenset(
    {
        "corpus_thresholds",
        "heldout_second_labeller",
        "zero_false_blocking",
        "coverage_agreement",
        "witness_replay",
        "redaction",
        "mined_conclusive_rate",
        "cache_parity",
        "deterministic_payload",
        "performance_targets",
    }
)
_REQUIRED_INPUT_ROLES = frozenset(
    {"authored_corpus", "heldout_corpus", "mined_set", "adjudication"}
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {path}")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ValueError(f"artifact root must be an object: {path}")
    return raw, value


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(ch in "0123456789abcdef" for ch in value[7:])
    )


def _unique_ids(value: Any) -> set[str] | None:
    if not isinstance(value, list) or not value:
        return None
    if any(not isinstance(item, str) or not item.strip() for item in value):
        return None
    identifiers = {item.strip() for item in value}
    return identifiers if len(identifiers) == len(value) else None


def _inside_root(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("input file path must be a non-empty canonical repository path")
    rel = Path(relative)
    if (
        rel.is_absolute()
        or rel.as_posix() != relative
        or any(part in ("", ".", "..") for part in rel.parts)
    ):
        raise ValueError(f"input file path is not repository-relative: {relative!r}")
    path = (root / rel).resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"input file resolves outside the repository: {relative!r}") from exc
    if not path.is_file():
        raise ValueError(f"input artifact is not a regular file: {relative!r}")
    return path


def validate_promotion_chain(spec: Any, repo_root: str | Path | None = None) -> list[str]:
    """Verify a promoted CheckSpec against its report and immutable record.

    Shadow checks need no promotion artifacts. For a promoted check, this verifies
    the non-circular hash links, input-file hashes, and the release report's complete
    requirement matrix. Missing evidence is always an error.
    """
    if spec.maturity == Maturity.SHADOW:
        if spec.promotion_record_hash:
            return [f"{spec.check_id}: shadow CheckSpec must not reference a promotion record"]
        return []

    errors: list[str] = []
    if spec.tier.value != "blocking":
        errors.append(f"{spec.check_id}: promoted checks must have blocking tier")
    if not spec.corpus_hash or not spec.heldout_corpus_hash or not spec.mined_corpus_id:
        errors.append(f"{spec.check_id}: promotion requires corpus, held-out, and mined-set identities")
    if not spec.toolchain_fingerprint:
        errors.append(f"{spec.check_id}: promotion requires a pinned toolchain fingerprint")
    if not _valid_sha256(spec.promotion_record_hash):
        errors.append(f"{spec.check_id}: promotion_record_hash is missing or malformed")
        return errors

    root = Path(repo_root).resolve() if repo_root is not None else Path(__file__).resolve().parents[2]
    artifact_dir = root / "evidence" / "release" / spec.check_id
    record_path = artifact_dir / "promotion_record.json"
    report_path = artifact_dir / "release_report.json"
    try:
        record_bytes, record = _read_json(record_path)
        report_bytes, report = _read_json(report_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{spec.check_id}: promotion evidence unavailable or invalid: {exc}")
        return errors

    if _sha256(record_bytes) != spec.promotion_record_hash:
        errors.append(f"{spec.check_id}: promotion record hash does not match the manifest")
    if record.get("schema") != PROMOTION_SCHEMA:
        errors.append(f"{spec.check_id}: unsupported promotion-record schema")
    if record.get("spec_core_hash") != spec.spec_core_hash:
        errors.append(f"{spec.check_id}: promotion record spec_core_hash mismatch")
    if record.get("target_maturity") != spec.maturity.value:
        errors.append(f"{spec.check_id}: promotion record maturity mismatch")
    if record.get("report_hash") != _sha256(report_bytes):
        errors.append(f"{spec.check_id}: promotion record report_hash mismatch")
    if record.get("toolchain_fingerprint") != spec.toolchain_fingerprint:
        errors.append(f"{spec.check_id}: promotion-record toolchain mismatch")
    created_date = record.get("created_date")
    try:
        parsed_date = date.fromisoformat(created_date) if isinstance(created_date, str) else None
        if parsed_date is None or parsed_date.isoformat() != created_date:
            raise ValueError
    except ValueError:
        errors.append(f"{spec.check_id}: promotion record created_date must be YYYY-MM-DD")

    if report.get("schema") != REPORT_SCHEMA:
        errors.append(f"{spec.check_id}: unsupported release-report schema")
    for key, expected in (
        ("check_id", spec.check_id),
        ("spec_core_hash", spec.spec_core_hash),
        ("target_maturity", spec.maturity.value),
        ("toolchain_fingerprint", spec.toolchain_fingerprint),
    ):
        if report.get(key) != expected:
            errors.append(f"{spec.check_id}: release report {key} mismatch")

    inputs = report.get("inputs")
    if not isinstance(inputs, dict):
        errors.append(f"{spec.check_id}: release report inputs must be an object")
        inputs = {}
    expected_inputs = {
        "corpus_hash": spec.corpus_hash,
        "heldout_corpus_hash": spec.heldout_corpus_hash,
        "mined_corpus_id": spec.mined_corpus_id,
    }
    for key, expected in expected_inputs.items():
        if inputs.get(key) != expected:
            errors.append(f"{spec.check_id}: release report inputs.{key} mismatch")
    for key in ("mined_snapshot_hash", "adjudication_hash"):
        if not _valid_sha256(inputs.get(key)):
            errors.append(f"{spec.check_id}: release report inputs.{key} must be a SHA-256 digest")

    measurement = report.get("measurement_command")
    if not isinstance(measurement, dict) or not all(
        isinstance(measurement.get(key), str) and measurement[key]
        for key in ("name", "version", "identity")
    ):
        errors.append(f"{spec.check_id}: release report must identify the measurement command")

    participants = report.get("participants")
    if not isinstance(participants, dict):
        errors.append(f"{spec.check_id}: release report must identify independent reviewers")
    else:
        authors = _unique_ids(participants.get("check_authors"))
        labellers = _unique_ids(participants.get("heldout_labellers"))
        adjudicators = _unique_ids(participants.get("adjudicators"))
        if authors is None or labellers is None or adjudicators is None:
            errors.append(f"{spec.check_id}: participant roles must be non-empty lists of unique IDs")
        else:
            if authors & labellers:
                errors.append(f"{spec.check_id}: held-out labellers must be independent of check authors")
            if authors & adjudicators:
                errors.append(f"{spec.check_id}: adjudicators must be independent of check authors")

    input_files = inputs.get("files", [])
    if not isinstance(input_files, list) or not input_files:
        errors.append(f"{spec.check_id}: release report must hash every evidence input file")
    else:
        seen_input_paths: set[str] = set()
        seen_roles: set[str] = set()
        for item in input_files:
            if not isinstance(item, dict) or not _valid_sha256(item.get("sha256")):
                errors.append(f"{spec.check_id}: malformed release input hash record")
                continue
            item_path = item.get("path")
            if not isinstance(item_path, str) or item_path in seen_input_paths:
                errors.append(f"{spec.check_id}: release input paths must be unique strings")
                continue
            seen_input_paths.add(item_path)
            role = item.get("role")
            if role not in _REQUIRED_INPUT_ROLES:
                errors.append(f"{spec.check_id}: unsupported or missing release input role for {item_path}")
            elif role in seen_roles:
                errors.append(f"{spec.check_id}: duplicate release input role: {role}")
            else:
                seen_roles.add(role)
            try:
                input_path = _inside_root(root, item_path)
                if _sha256(input_path.read_bytes()) != item["sha256"]:
                    errors.append(f"{spec.check_id}: release input hash mismatch: {item_path}")
            except (OSError, ValueError) as exc:
                errors.append(f"{spec.check_id}: invalid release input {item.get('path')!r}: {exc}")
        missing_roles = sorted(_REQUIRED_INPUT_ROLES - seen_roles)
        if missing_roles:
            errors.append(f"{spec.check_id}: release report missing hashed input roles: {', '.join(missing_roles)}")

    requirements = report.get("requirements")
    if not isinstance(requirements, dict):
        errors.append(f"{spec.check_id}: release report requirements must be an object")
    else:
        missing = sorted(_REQUIRED_REQUIREMENTS - set(requirements))
        if missing:
            errors.append(f"{spec.check_id}: release report missing requirements: {', '.join(missing)}")
        for requirement, result in requirements.items():
            if not isinstance(result, dict) or result.get("passed") is not True:
                errors.append(f"{spec.check_id}: release requirement not met: {requirement}")

    return errors


__all__ = ["PROMOTION_SCHEMA", "REPORT_SCHEMA", "validate_promotion_chain"]
