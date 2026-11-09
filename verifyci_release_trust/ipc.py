"""Strict Hostile-Input IPC Protocol and Schema Validator (§15.10 Component D).

Treats every worker response as adversarial. Enforces strict UTF-8 decoding,
rejects duplicate keys, constant non-finites (NaN/Infinity), deeply nested structures,
oversized collections, and enforces consistency between exit codes and claimed outcomes.
"""
from __future__ import annotations

import decimal
import json
from typing import Any, NamedTuple

MAX_IPC_BYTES = 1_048_576  # 1 MB
MAX_DEPTH = 10
MAX_STRING_LENGTH = 65_536
MAX_COLLECTION_SIZE = 1_000
MAX_SAFE_INTEGER = 2**53 - 1
MIN_SAFE_INTEGER = -(2**53 - 1)

EXIT_CODE_MAP = {
    0: "PASS",
    1: "FAIL",
    2: "INCONCLUSIVE",
    3: "ERROR",
    # Worker-only mapping for a case where the check is not applicable to the
    # scenario (the CLI's exit code 4 means REVIEW; that value never crosses
    # this boundary).
    4: "NOT_APPLICABLE",
}

# The canonical Coverage enum is COMPLETE/PARTIAL/UNKNOWN; FULL/NONE are legacy
# worker spellings retained for fixture compatibility.
VALID_COVERAGE = frozenset({"COMPLETE", "PARTIAL", "UNKNOWN", "FULL", "NONE"})
VALID_OUTCOMES = frozenset({"PASS", "FAIL", "INCONCLUSIVE", "ERROR", "NOT_APPLICABLE"})


class IPCParseResult(NamedTuple):
    data: dict[str, Any] | None
    outcome: str
    error: str | None


def _reject_constants(val: str) -> None:
    raise ValueError(f"unsupported or non-finite JSON constant: {val!r}")


def _duplicate_key_rejecting_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if len(pairs) > MAX_COLLECTION_SIZE:
        raise ValueError(f"JSON object contains {len(pairs)} keys, exceeding limit {MAX_COLLECTION_SIZE}")
    for k, v in pairs:
        if not isinstance(k, str):
            raise ValueError(f"non-string JSON key: {type(k).__name__}")
        if len(k) > 256:
            raise ValueError(f"JSON key length {len(k)} exceeds maximum 256 characters")
        if k in d:
            raise ValueError(f"duplicate JSON key detected: {k!r}")
        d[k] = v
    return d


def validate_rfc8785_and_depth(node: Any, depth: int = 0) -> None:
    """Validate nesting depth, string lengths, collection sizes, and RFC 8785 numeric domains."""
    if depth > MAX_DEPTH:
        raise ValueError(f"JSON nesting depth exceeds maximum of {MAX_DEPTH}")

    if isinstance(node, str):
        if len(node) > MAX_STRING_LENGTH:
            raise ValueError(f"JSON string length {len(node)} exceeds maximum of {MAX_STRING_LENGTH}")
    elif isinstance(node, (decimal.Decimal, int, float)):
        dec = decimal.Decimal(str(node)) if isinstance(node, float) else decimal.Decimal(node)
        if not dec.is_finite():
            raise ValueError(f"non-finite numeric value: {dec}")
        if dec == dec.to_integral_value():
            int_val = int(dec)
            if int_val > MAX_SAFE_INTEGER or int_val < MIN_SAFE_INTEGER:
                raise ValueError(f"integer {int_val} outside safe RFC 8785 IEEE-754 range")
    elif isinstance(node, dict):
        if len(node) > MAX_COLLECTION_SIZE:
            raise ValueError(f"dict size {len(node)} exceeds limit {MAX_COLLECTION_SIZE}")
        for k, v in node.items():
            if len(k) > 256:
                raise ValueError("dict key exceeds 256 characters")
            validate_rfc8785_and_depth(v, depth + 1)
    elif isinstance(node, (list, tuple)):
        if len(node) > MAX_COLLECTION_SIZE:
            raise ValueError(f"list size {len(node)} exceeds limit {MAX_COLLECTION_SIZE}")
        for item in node:
            validate_rfc8785_and_depth(item, depth + 1)
    elif node is not None and not isinstance(node, bool):
        raise ValueError(f"unsupported JSON value type: {type(node).__name__}")


def validate_check_result_schema(obj: Any) -> tuple[bool, str | None]:
    """Enforce exact schema expected from worker response."""
    if not isinstance(obj, dict):
        return False, f"worker output root must be a JSON object, got {type(obj).__name__}"

    required_fields = {"outcome", "coverage", "reason_codes", "findings"}
    keys = set(obj.keys())
    if not required_fields.issubset(keys):
        missing = required_fields - keys
        return False, f"missing required schema fields: {missing}"

    # Extra fields rejected unless declared
    allowed_fields = required_fields | {"defect_metrics", "diagnostics", "toolchain_fingerprint"}
    extra = keys - allowed_fields
    if extra:
        return False, f"unexpected fields in worker response: {extra}"

    outcome = obj.get("outcome")
    if outcome not in VALID_OUTCOMES:
        return False, f"invalid outcome value: {outcome!r}"

    coverage = obj.get("coverage")
    if coverage not in VALID_COVERAGE:
        return False, f"invalid coverage value: {coverage!r}"

    reason_codes = obj.get("reason_codes")
    if not isinstance(reason_codes, list) or not all(isinstance(rc, str) for rc in reason_codes):
        return False, "reason_codes must be a list of strings"

    findings = obj.get("findings")
    if not isinstance(findings, list):
        return False, "findings must be a list of finding objects"

    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            return False, f"findings[{idx}] must be a dict"
        if "defect_id" not in f or not isinstance(f.get("defect_id"), str):
            return False, f"findings[{idx}] missing valid string 'defect_id'"

    return True, None


def parse_strict_ipc_payload(raw_bytes: bytes, exit_code: int) -> IPCParseResult:
    """Parse, validate, and verify exit-code consistency for candidate worker response."""
    if len(raw_bytes) > MAX_IPC_BYTES:
        return IPCParseResult(None, "INCONCLUSIVE", f"payload size {len(raw_bytes)} exceeds {MAX_IPC_BYTES} bytes")

    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        return IPCParseResult(None, "INCONCLUSIVE", f"invalid UTF-8 in worker response: {exc}")

    trimmed = text.strip()
    if not trimmed:
        if exit_code == 0:
            return IPCParseResult(None, "INCONCLUSIVE", "empty worker response with zero exit code")
        mapped = EXIT_CODE_MAP.get(exit_code, "INCONCLUSIVE")
        return IPCParseResult(None, mapped, f"worker exited with code {exit_code} and produced no output")

    try:
        decoder = json.JSONDecoder(
            object_pairs_hook=_duplicate_key_rejecting_hook,
            parse_float=decimal.Decimal,
            parse_constant=_reject_constants,
        )
        data, end_idx = decoder.raw_decode(trimmed)
    except Exception as exc:
        return IPCParseResult(None, "INCONCLUSIVE", f"malformed JSON from worker: {exc}")

    # Check for trailing non-whitespace data or multiple objects
    trailing = trimmed[end_idx:].strip()
    if trailing:
        return IPCParseResult(None, "INCONCLUSIVE", "worker emitted trailing data or multiple JSON objects")

    try:
        validate_rfc8785_and_depth(data)
    except Exception as exc:
        return IPCParseResult(None, "INCONCLUSIVE", f"RFC 8785/depth validation failed: {exc}")

    is_valid_schema, schema_err = validate_check_result_schema(data)
    if not is_valid_schema:
        return IPCParseResult(None, "INCONCLUSIVE", f"schema validation error: {schema_err}")

    claimed_outcome = data["outcome"]

    # Exit code vs claimed outcome consistency check
    expected_outcome_for_exit = EXIT_CODE_MAP.get(exit_code)
    if expected_outcome_for_exit is None:
        return IPCParseResult(None, "INCONCLUSIVE", f"unrecognized process exit code {exit_code}")

    if exit_code == 0 and claimed_outcome != "PASS":
        return IPCParseResult(None, "INCONCLUSIVE", f"exit code 0 inconsistent with outcome {claimed_outcome!r}")
    if exit_code == 1 and claimed_outcome != "FAIL":
        return IPCParseResult(None, "INCONCLUSIVE", f"exit code 1 inconsistent with outcome {claimed_outcome!r}")
    if exit_code == 2 and claimed_outcome != "INCONCLUSIVE":
        return IPCParseResult(None, "INCONCLUSIVE", f"exit code 2 inconsistent with outcome {claimed_outcome!r}")
    if exit_code == 3 and claimed_outcome != "ERROR":
        return IPCParseResult(None, "INCONCLUSIVE", f"exit code 3 inconsistent with outcome {claimed_outcome!r}")
    if exit_code == 4 and claimed_outcome != "NOT_APPLICABLE":
        return IPCParseResult(None, "INCONCLUSIVE", f"exit code 4 inconsistent with outcome {claimed_outcome!r}")

    return IPCParseResult(data, claimed_outcome, None)
