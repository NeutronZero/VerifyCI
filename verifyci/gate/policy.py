"""Target-base policy loading, schema validation, and PR policy review.

Policy is declarative TOML.  It never executes code and never uses user
regular expressions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from hashlib import sha256
import json
import re
import tomllib
from typing import Any, Mapping

from verifyci.contracts.model import (
    AcceptanceRecord,
    Policy,
    WaiverRecord,
)
from verifyci.contracts.names import (
    glob_union_is_universal,
    parse_qualified_name,
    validate_glob_pattern,
)
from verifyci.contracts.reason_codes import DEFECT_REASON_CODES, GAPS, is_acceptable_gap
from verifyci.scm.git import GitRepo


POLICY_PATH = ".verifyci/policy.toml"
_BUILTIN_POLICY_ID = "builtin_bootstrap_v1"
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHECK_IDS = {"grounding", "deletion", "contract", "semantic", "security"}
_SINK_KINDS = {"sql", "log", "network", "file", "exec", "serialize", "html"}
_TOP_LEVEL = {
    "gate",
    "paths",
    "entrypoints",
    "public_api",
    "deny_changes",
    "protected_guards",
    "protected_errors",
    "taint",
    "forbidden_calls",
    "decorators",
    "calls",
    "secrets",
    "waivers",
    "coverage_acceptances",
    "version",
}


class PolicyError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class ProposedReview:
    policy: Policy
    review_reasons: tuple[str, ...]
    superseded_entries: frozenset[str]
    diagnostics: tuple[Mapping[str, Any], ...] = ()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash_bytes(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def _hash_object(value: Any) -> str:
    return _hash_bytes(canonical_bytes(value))


def _parse_date(value: Any, field: str, record_id: str) -> date:
    if not isinstance(value, str) or not _DATE_RE.match(value):
        raise PolicyError("invalid_policy", f"{record_id}: {field} must be YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise PolicyError("invalid_policy", f"{record_id}: invalid {field}: {value!r}") from exc


def _nonempty_str(value: Any, field: str, record_id: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError("invalid_policy", f"{record_id}: {field} must be a non-empty string")
    return value.strip()


def _string_list(value: Any, field: str, record_id: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyError("invalid_policy", f"{record_id}: {field} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PolicyError("invalid_policy", f"{record_id}: {field} entries must be strings")
        out.append(item.strip())
    return tuple(out)


def _path_globs(value: Any, field: str, record_id: str) -> tuple[str, ...]:
    items = _string_list(value, field, record_id)
    out: list[str] = []
    for item in items:
        try:
            out.append(validate_glob_pattern(item))
        except ValueError as exc:
            raise PolicyError("invalid_policy", f"{record_id}: {field}: {exc}") from exc
    return tuple(out)


def _qualified(value: Any, field: str, record_id: str) -> str:
    text = _nonempty_str(value, field, record_id)
    try:
        parse_qualified_name(text)
    except ValueError as exc:
        raise PolicyError("invalid_policy", f"{record_id}: {field}: {exc}") from exc
    return text


def _qualified_list(value: Any, field: str, record_id: str) -> tuple[str, ...]:
    items = _string_list(value, field, record_id)
    for item in items:
        try:
            parse_qualified_name(item)
        except ValueError as exc:
            raise PolicyError("invalid_policy", f"{record_id}: {field}: {exc}") from exc
    return tuple(items)


def _table(value: Any, field: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError("invalid_policy", f"{field} must be a table")
    return value


def _validate_policy_object(data: Mapping[str, Any]) -> None:
    unknown = set(data) - _TOP_LEVEL
    if unknown:
        raise PolicyError("invalid_policy", f"unknown policy keys: {sorted(unknown)}")

    gate = _table(data.get("gate"), "gate")
    if gate:
        allowed = {"cold_deadline_seconds", "warm_deadline_seconds", "target_drift"}
        unknown = set(gate) - allowed
        if unknown:
            raise PolicyError("invalid_policy", f"unknown [gate] keys: {sorted(unknown)}")
        drift = gate.get("target_drift", "record")
        if drift not in ("record", "require_zero"):
            raise PolicyError("invalid_policy", "[gate].target_drift must be 'record' or 'require_zero'")
        for key in ("cold_deadline_seconds", "warm_deadline_seconds"):
            if key in gate and (not isinstance(gate[key], int) or gate[key] <= 0):
                raise PolicyError("invalid_policy", f"[gate].{key} must be a positive integer")

    paths = _table(data.get("paths"), "paths")
    for key, value in paths.items():
        if key not in ("generated", "vendored", "tests", "binary", "source_roots"):
            raise PolicyError("invalid_policy", f"unknown [paths] key {key!r}")
        if key == "source_roots":
            roots = _string_list(value, key, "paths") if value else ()
            for root in roots:
                if root != "." and not validate_safe_root(root):
                    raise PolicyError("invalid_policy", f"paths.source_roots entry is not repository-relative: {root!r}")
        else:
            _path_globs(value, key, "paths")

    for table_name in ("entrypoints", "public_api"):
        table = _table(data.get(table_name), table_name)
        for key in table:
            if key not in ("symbols", "globs"):
                raise PolicyError("invalid_policy", f"unknown [{table_name}] key {key!r}")
        if "symbols" in table:
            _string_list(table["symbols"], "symbols", table_name)
        if "globs" in table:
            _string_list(table["globs"], "globs", table_name)

    for rule_id, rule in _table(data.get("deny_changes"), "deny_changes").items():
        if not isinstance(rule, dict):
            raise PolicyError("invalid_policy", f"deny_changes.{rule_id} must be a table")
        unknown = set(rule) - {"paths", "symbols", "reason"}
        if unknown:
            raise PolicyError("invalid_policy", f"unknown deny_changes.{rule_id} keys: {sorted(unknown)}")
        paths = _path_globs(rule["paths"], "paths", f"deny_changes.{rule_id}") if "paths" in rule else ()
        symbols = _qualified_list(rule["symbols"], "symbols", f"deny_changes.{rule_id}") if "symbols" in rule else ()
        if not paths and not symbols:
            raise PolicyError("invalid_policy", f"deny_changes.{rule_id} requires paths or symbols")
        _nonempty_str(rule.get("reason"), "reason", f"deny_changes.{rule_id}")

    for rule_id, rule in _table(data.get("protected_guards"), "protected_guards").items():
        if not isinstance(rule, dict):
            raise PolicyError("invalid_policy", f"protected_guards.{rule_id} must be a table")
        unknown = set(rule) - {"effects", "guard_calls", "paths", "reason"}
        if unknown:
            raise PolicyError("invalid_policy", f"unknown protected_guards.{rule_id} keys: {sorted(unknown)}")
        effects = _string_list(rule.get("effects"), "effects", f"protected_guards.{rule_id}")
        guard_paths = _path_globs(rule.get("paths"), "paths", f"protected_guards.{rule_id}")
        if not effects or not guard_paths:
            raise PolicyError("invalid_policy", f"protected_guards.{rule_id} requires effects and paths")
        if "guard_calls" in rule:
            _qualified_list(rule["guard_calls"], "guard_calls", f"protected_guards.{rule_id}")
        _nonempty_str(rule.get("reason"), "reason", f"protected_guards.{rule_id}")

    for rule_id, rule in _table(data.get("protected_errors"), "protected_errors").items():
        if not isinstance(rule, dict):
            raise PolicyError("invalid_policy", f"protected_errors.{rule_id} must be a table")
        unknown = set(rule) - {"raises", "paths", "reason"}
        if unknown:
            raise PolicyError("invalid_policy", f"unknown protected_errors.{rule_id} keys: {sorted(unknown)}")
        raises = _qualified_list(rule.get("raises"), "raises", f"protected_errors.{rule_id}")
        error_paths = _path_globs(rule.get("paths"), "paths", f"protected_errors.{rule_id}")
        if not raises or not error_paths:
            raise PolicyError("invalid_policy", f"protected_errors.{rule_id} requires raises and paths")
        _nonempty_str(rule.get("reason"), "reason", f"protected_errors.{rule_id}")

    taint = _table(data.get("taint"), "taint")
    if taint:
        allowed = {"sources", "sinks", "sanitizers"}
        unknown = set(taint) - allowed
        if unknown:
            raise PolicyError("invalid_policy", f"unknown [taint] keys: {sorted(unknown)}")
        if "sources" in taint:
            _string_list(taint["sources"], "sources", "taint")
        for sink_id, sink in _table(taint.get("sinks"), "taint.sinks").items():
            if not isinstance(sink, dict):
                raise PolicyError("invalid_policy", f"taint.sinks.{sink_id} must be a table")
            if not _string_list(sink.get("symbols"), "symbols", f"taint.sinks.{sink_id}"):
                raise PolicyError("invalid_policy", f"taint.sinks.{sink_id} requires symbols")
            if sink.get("kind") not in _SINK_KINDS:
                raise PolicyError("invalid_policy", f"taint.sinks.{sink_id}.kind is invalid")
        for sanitizer_id, sanitizer in _table(taint.get("sanitizers"), "taint.sanitizers").items():
            if not isinstance(sanitizer, dict):
                raise PolicyError("invalid_policy", f"taint.sanitizers.{sanitizer_id} must be a table")
            _qualified_list(sanitizer.get("symbols"), "symbols", f"taint.sanitizers.{sanitizer_id}")
            _string_list(sanitizer.get("sinks"), "sinks", f"taint.sanitizers.{sanitizer_id}")

    for rule_id, rule in _table(data.get("forbidden_calls"), "forbidden_calls").items():
        if not isinstance(rule, dict):
            raise PolicyError("invalid_policy", f"forbidden_calls.{rule_id} must be a table")
        if not _string_list(rule.get("symbols"), "symbols", f"forbidden_calls.{rule_id}"):
            raise PolicyError("invalid_policy", f"forbidden_calls.{rule_id} requires symbols")
        _nonempty_str(rule.get("reason"), "reason", f"forbidden_calls.{rule_id}")

    decorators = _table(data.get("decorators"), "decorators")
    if decorators:
        unknown = set(decorators) - {"transparent"}
        if unknown:
            raise PolicyError("invalid_policy", f"unknown [decorators] keys: {sorted(unknown)}")
        transparent = _table(decorators.get("transparent"), "decorators.transparent")
        if transparent and "symbols" in transparent:
            _qualified_list(transparent["symbols"], "symbols", "decorators.transparent")

    calls = _table(data.get("calls"), "calls")
    if calls:
        models = _table(calls.get("models"), "calls.models")
        for model_id, model in models.items():
            if not isinstance(model, dict):
                raise PolicyError("invalid_policy", f"calls.models.{model_id} must be a table")
            if not _string_list(model.get("symbols"), "symbols", f"calls.models.{model_id}"):
                raise PolicyError("invalid_policy", f"calls.models.{model_id} requires symbols")
            if model.get("model") != "pure":
                raise PolicyError("invalid_policy", f"calls.models.{model_id}.model must be 'pure'")

    secrets = _table(data.get("secrets"), "secrets")
    if secrets:
        unknown = set(secrets) - {"allowlist_paths", "placeholder_patterns"}
        if unknown:
            raise PolicyError("invalid_policy", f"unknown [secrets] keys: {sorted(unknown)}")
        if "allowlist_paths" in secrets:
            _path_globs(secrets["allowlist_paths"], "allowlist_paths", "secrets")
        if "placeholder_patterns" in secrets:
            _string_list(secrets["placeholder_patterns"], "placeholder_patterns", "secrets")

    _validate_waivers(_table(data.get("waivers"), "waivers"))
    _validate_acceptances(_table(data.get("coverage_acceptances"), "coverage_acceptances"))


def validate_safe_root(root: str) -> bool:
    if not isinstance(root, str) or not root or root.startswith("/") or "\\" in root:
        return False
    return all(part not in ("", ".", "..") for part in root.split("/"))


def _validate_waivers(waivers: Mapping[str, Any]) -> None:
    for record_id, raw in waivers.items():
        if not isinstance(raw, dict):
            raise PolicyError("invalid_policy", f"waivers.{record_id} must be a table")
        unknown = set(raw) - {
            "check", "defect_id", "fingerprint", "reason", "approved_by", "created", "expires",
        }
        if unknown:
            raise PolicyError("invalid_policy", f"unknown waivers.{record_id} keys: {sorted(unknown)}")
        check = _nonempty_str(raw.get("check"), "check", f"waivers.{record_id}")
        if check not in _CHECK_IDS:
            raise PolicyError("invalid_policy", f"waivers.{record_id}.check is unknown")
        defect_id = _nonempty_str(raw.get("defect_id"), "defect_id", f"waivers.{record_id}")
        if defect_id not in DEFECT_REASON_CODES:
            raise PolicyError("invalid_policy", f"waivers.{record_id}.defect_id is unknown")
        fingerprint = _nonempty_str(raw.get("fingerprint"), "fingerprint", f"waivers.{record_id}")
        if not _FINGERPRINT_RE.match(fingerprint):
            raise PolicyError("invalid_policy", f"waivers.{record_id}.fingerprint must be sha256:<64 hex>")
        _nonempty_str(raw.get("reason"), "reason", f"waivers.{record_id}")
        _nonempty_str(raw.get("approved_by"), "approved_by", f"waivers.{record_id}")
        created = _parse_date(raw.get("created"), "created", f"waivers.{record_id}")
        expires = _parse_date(raw.get("expires"), "expires", f"waivers.{record_id}")
        if expires < created:
            raise PolicyError("invalid_policy", f"waivers.{record_id}: expires < created")


def _validate_acceptances(acceptances: Mapping[str, Any]) -> None:
    for record_id, raw in acceptances.items():
        if not isinstance(raw, dict):
            raise PolicyError("invalid_policy", f"coverage_acceptances.{record_id} must be a table")
        unknown = set(raw) - {
            "check", "reason_code", "paths", "symbols", "reason", "approved_by", "created", "expires",
        }
        if unknown:
            raise PolicyError("invalid_policy", f"unknown coverage_acceptances.{record_id} keys: {sorted(unknown)}")
        check = _nonempty_str(raw.get("check"), "check", f"coverage_acceptances.{record_id}")
        if check not in _CHECK_IDS:
            raise PolicyError("invalid_policy", f"coverage_acceptances.{record_id}.check is unknown")
        reason_code = _nonempty_str(raw.get("reason_code"), "reason_code", f"coverage_acceptances.{record_id}")
        if reason_code not in GAPS or not is_acceptable_gap(reason_code):
            raise PolicyError("invalid_policy", f"coverage_acceptances.{record_id}.reason_code is not acceptable")
        paths = _path_globs(raw["paths"], "paths", f"coverage_acceptances.{record_id}") if "paths" in raw else ()
        symbols = _qualified_list(raw["symbols"], "symbols", f"coverage_acceptances.{record_id}") if "symbols" in raw else ()
        if not paths and not symbols:
            raise PolicyError("invalid_policy", f"coverage_acceptances.{record_id} requires paths or symbols")
        if paths and glob_union_is_universal(paths):
            raise PolicyError("invalid_policy", f"coverage_acceptances.{record_id} has a universal path scope")
        _nonempty_str(raw.get("reason"), "reason", f"coverage_acceptances.{record_id}")
        _nonempty_str(raw.get("approved_by"), "approved_by", f"coverage_acceptances.{record_id}")
        created = _parse_date(raw.get("created"), "created", f"coverage_acceptances.{record_id}")
        expires = _parse_date(raw.get("expires"), "expires", f"coverage_acceptances.{record_id}")
        lifetime = (expires - created).days
        if lifetime < 0 or lifetime > 180:
            raise PolicyError("invalid_policy", f"coverage_acceptances.{record_id}: lifetime must be 0..180 days")


def _build_policy(data: Mapping[str, Any], *, blob_hash: str | None, source: str) -> Policy:
    gate = dict(_table(data.get("gate"), "gate"))
    paths = dict(_table(data.get("paths"), "paths"))
    entrypoints = dict(_table(data.get("entrypoints"), "entrypoints"))
    public_api = dict(_table(data.get("public_api"), "public_api"))
    deny = dict(_table(data.get("deny_changes"), "deny_changes"))
    guards = dict(_table(data.get("protected_guards"), "protected_guards"))
    errors = dict(_table(data.get("protected_errors"), "protected_errors"))
    taint = dict(_table(data.get("taint"), "taint"))
    forbidden = dict(_table(data.get("forbidden_calls"), "forbidden_calls"))
    decorators = dict(_table(data.get("decorators"), "decorators"))
    calls = dict(_table(data.get("calls"), "calls"))
    secrets = dict(_table(data.get("secrets"), "secrets"))

    waivers: dict[str, WaiverRecord] = {}
    for record_id, raw in _table(data.get("waivers"), "waivers").items():
        waivers[record_id] = WaiverRecord(
            record_id=record_id,
            check=str(raw["check"]).strip(),
            defect_id=str(raw["defect_id"]).strip(),
            fingerprint=str(raw["fingerprint"]).strip(),
            reason=str(raw["reason"]).strip(),
            approved_by=str(raw["approved_by"]).strip(),
            created=str(raw["created"]).strip(),
            expires=str(raw["expires"]).strip(),
            raw=dict(raw),
        )
    acceptances: dict[str, AcceptanceRecord] = {}
    for record_id, raw in _table(data.get("coverage_acceptances"), "coverage_acceptances").items():
        acceptances[record_id] = AcceptanceRecord(
            record_id=record_id,
            check=str(raw["check"]).strip(),
            reason_code=str(raw["reason_code"]).strip(),
            paths=tuple(str(p).strip() for p in raw.get("paths", ())),
            symbols=tuple(str(s).strip() for s in raw.get("symbols", ())),
            reason=str(raw["reason"]).strip(),
            approved_by=str(raw["approved_by"]).strip(),
            created=str(raw["created"]).strip(),
            expires=str(raw["expires"]).strip(),
            raw=dict(raw),
        )

    effective_hash = blob_hash or _hash_object(data)
    return Policy(
        raw=dict(data),
        blob_hash=blob_hash,
        source=source,
        effective_hash=effective_hash,
        gate=gate,
        path_classes={k: tuple(v) for k, v in paths.items() if isinstance(v, list)},
        entrypoints={k: tuple(v) for k, v in entrypoints.items() if isinstance(v, list)},
        public_api={k: tuple(v) for k, v in public_api.items() if isinstance(v, list)},
        deny_changes={k: dict(v) for k, v in deny.items()},
        protected_guards={k: dict(v) for k, v in guards.items()},
        protected_errors={k: dict(v) for k, v in errors.items()},
        taint_sources=tuple(taint.get("sources", ())),
        taint_sinks={k: dict(v) for k, v in _table(taint.get("sinks"), "taint.sinks").items()},
        taint_sanitizers={k: dict(v) for k, v in _table(taint.get("sanitizers"), "taint.sanitizers").items()},
        forbidden_calls={k: dict(v) for k, v in forbidden.items()},
        transparent_decorators=tuple(
            _table(decorators.get("transparent"), "decorators.transparent").get("symbols", ())
        ),
        call_models={k: dict(v) for k, v in _table(calls.get("models"), "calls.models").items()},
        secret_allowlist_paths=tuple(secrets.get("allowlist_paths", ())),
        secret_placeholders=tuple(secrets.get("placeholder_patterns", ())),
        waivers=waivers,
        acceptances=acceptances,
    )


def parse_policy_bytes(data: bytes, *, source: str = "target_blob", blob_hash: str | None = None) -> Policy:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError("invalid_policy", "policy is not valid UTF-8") from exc
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError("invalid_policy", f"invalid TOML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PolicyError("invalid_policy", "policy root must be a table")
    _validate_policy_object(parsed)
    hash_value = None
    if blob_hash:
        hash_value = "sha256:" + blob_hash.removeprefix("sha256:")
    return _build_policy(parsed, blob_hash=hash_value, source=source)


def load_policy_at(git: GitRepo, rev: str) -> Policy | None:
    raw = git.read_path_at(rev, POLICY_PATH)
    if raw is None:
        return None
    return parse_policy_bytes(raw, source="target_blob", blob_hash=sha256(raw).hexdigest())


_BUILTIN_BOOTSTRAP_OBJECT: dict[str, Any] = {
    "gate": {"target_drift": "record"},
    "paths": {},
    "entrypoints": {"symbols": []},
    "public_api": {"symbols": []},
    "deny_changes": {},
    "protected_guards": {},
    "protected_errors": {},
    "taint": {"sources": [], "sinks": {}, "sanitizers": {}},
    "forbidden_calls": {},
    "decorators": {"transparent": {"symbols": []}},
    "calls": {"models": {}},
    "secrets": {"allowlist_paths": [], "placeholder_patterns": []},
    "waivers": {},
    "coverage_acceptances": {},
}
BUILTIN_BOOTSTRAP_HASH = _hash_object(_BUILTIN_BOOTSTRAP_OBJECT)


def builtin_bootstrap_policy() -> Policy:
    # Validate the embedded object through the same path as user policy.
    _validate_policy_object(_BUILTIN_BOOTSTRAP_OBJECT)
    return _build_policy(
        _BUILTIN_BOOTSTRAP_OBJECT,
        blob_hash=None,
        source=_BUILTIN_POLICY_ID,
    )


def _record_map(policy: Policy) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for record_id, waiver in policy.waivers.items():
        out[f"waivers:{record_id}"] = waiver.normalized()
    for record_id, acceptance in policy.acceptances.items():
        out[f"coverage_acceptances:{record_id}"] = acceptance.normalized()
    return out


def review_proposed_policy(
    authoritative: Policy,
    proposed_data: bytes,
    *,
    as_of_date: str,
) -> ProposedReview:
    """Validate a PR-authored policy against the authoritative policy.

    The proposal is never authoritative for suppressing findings in this run.
    This function only detects schema errors and the review conditions that the
    proposal creates or remediates.
    """
    proposed = parse_policy_bytes(
        proposed_data,
        source="proposed_blob",
        blob_hash=sha256(proposed_data).hexdigest(),
    )
    authoritative_records = _record_map(authoritative)
    proposed_records = _record_map(proposed)
    for key, record in proposed_records.items():
        if key not in authoritative_records or authoritative_records[key] != record:
            created = str(record.get("created", ""))
            if created > as_of_date:
                raise PolicyError(
                    "invalid_policy",
                    f"{key}: newly added or modified record has created {created} > as_of {as_of_date}",
                )

    review_reasons: set[str] = set()
    diagnostics: list[dict[str, Any]] = []
    superseded: set[str] = set()

    # Any expired or not-yet-effective entry left in the proposed policy is a
    # review condition, even when it matches nothing in this run.
    for record_id, waiver in proposed.waivers.items():
        if not waiver.active(as_of_date):
            review_reasons.add("waiver_review")
            diagnostics.append(
                {
                    "code": "stale_waiver_present",
                    "record_id": record_id,
                    "created": waiver.created,
                    "expires": waiver.expires,
                }
            )
    for record_id, acceptance in proposed.acceptances.items():
        if not acceptance.active(as_of_date):
            review_reasons.add("coverage_acceptance_review")
            diagnostics.append(
                {
                    "code": "stale_acceptance_present",
                    "record_id": record_id,
                    "created": acceptance.created,
                    "expires": acceptance.expires,
                }
            )

    # Detect authoritative stale entries removed or validly renewed.  The
    # supersession boundary is applied by the orchestrator only when no other
    # blocker remains.
    for key, record in authoritative_records.items():
        namespace, record_id = key.split(":", 1)
        if namespace == "waivers":
            auth = authoritative.waivers[record_id]
            candidate = proposed.waivers.get(record_id)
            if not auth.active(as_of_date) and (candidate is None or candidate.active(as_of_date)):
                superseded.add(key)
        else:
            auth = authoritative.acceptances[record_id]
            candidate = proposed.acceptances.get(record_id)
            if not auth.active(as_of_date) and (candidate is None or candidate.active(as_of_date)):
                superseded.add(key)
    return ProposedReview(
        policy=proposed,
        review_reasons=tuple(sorted(review_reasons)),
        superseded_entries=frozenset(superseded),
        diagnostics=tuple(diagnostics),
    )


__all__ = [
    "BUILTIN_BOOTSTRAP_HASH",
    "POLICY_PATH",
    "PolicyError",
    "ProposedReview",
    "builtin_bootstrap_policy",
    "canonical_bytes",
    "load_policy_at",
    "parse_policy_bytes",
    "review_proposed_policy",
]
