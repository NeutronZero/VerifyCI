"""Project invariant configuration: repo-local, default-on.

Invariants are project-specific facts, so they live with the code: a
`invariants.yaml` next to the DB (i.e. `<repo>/.verifyci/invariants.yaml`).
`run_verify` loads it by default — not an opt-in flag — and its rules run
*in addition to* the built-ins, so the common path can never silently
revert to the hardcoded pair.

Flat list only (`forbid_call:`, `forbid_import:`, `secrets_scan`,
`provenance_check`). Scope-conditional rules wait until a flat list is
proven insufficient (Principle 6).

Sharp edge, stated plainly: a typo'd rule (missing `query`, or an unknown
kind like `forbid_imports:`) fails closed — every diff FAILs until fixed.
That is intentional (an unevaluable rule must block, not vanish), but it
means a typo reads as a blocker. The checker's explanation names the
unknown kind; the fix is spelling, not policy.

```yaml
invariants:
  - id: no-sync-in-sansio
    rule: sansio must not import sync flask modules
    query: "forbid_import:..config"
    blocking: true
```
"""
import os

from verifyci.contracts.verification_ir import Invariant, SignedIntentWaiver
from verifyci.verification.defaults import default_invariants

FILENAME = "invariants.yaml"
WAIVERS_FILENAME = "waivers.yaml"


def repo_invariants_path(db_path: str | None) -> str | None:
    if not db_path:
        return None
    candidate = os.path.join(os.path.dirname(os.path.abspath(db_path)), FILENAME)
    return candidate if os.path.exists(candidate) else None


def load_repo_invariants(db_path: str | None = None, path: str | None = None) -> list[Invariant]:
    """Built-ins plus repo-local rules. Missing file == built-ins only
    (quiet). Malformed file raises (loud — a broken gate config must never
    silently fall back). Empty file == no repo rules (quiet)."""
    resolved = path or repo_invariants_path(db_path)
    if not resolved:
        return default_invariants()
    return default_invariants() + _load_file(resolved)


def repo_waivers_path(db_path: str | None) -> str | None:
    if not db_path:
        return None
    candidate = os.path.join(os.path.dirname(os.path.abspath(db_path)), WAIVERS_FILENAME)
    return candidate if os.path.exists(candidate) else None


def load_repo_waivers(db_path: str | None = None, path: str | None = None) -> list[SignedIntentWaiver]:
    """Load repo-local signed intent waivers (<repo>/.verifyci/waivers.yaml).
    Missing file == no waivers (quiet).
    Malformed file raises ValueError (loud — broken gate configuration fails closed).
    """
    resolved = path or repo_waivers_path(db_path)
    if not resolved:
        return []
    return _load_waivers_file(resolved)


def _load_waivers_file(path: str) -> list[SignedIntentWaiver]:
    import yaml
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        raise ValueError(f"malformed waivers file {path}: {e}") from e
    data = data or {}
    waivers = []
    for i, item in enumerate(data.get("waivers", []) or []):
        if not isinstance(item, dict):
            raise ValueError(f"waiver entry #{i} in {path} must be a mapping")
        waiver_id = str(item.get("id") or item.get("waiver_id", f"waiver-{i}"))
        target = str(item.get("target", ""))
        signer = str(item.get("signer", ""))
        signature = str(item.get("signature", ""))
        reason = str(item.get("reason", ""))
        valid = bool(item.get("valid", True))
        algorithm = str(item.get("algorithm", "hmac-sha256"))
        key_id = str(item.get("key_id", ""))
        waivers.append(SignedIntentWaiver(
            waiver_id=waiver_id,
            target=target,
            signer=signer,
            signature=signature,
            reason=reason,
            valid=valid,
            algorithm=algorithm,
            key_id=key_id,
        ))
    return waivers


VALID_TARGET_SCOPES = ("code_core", "code_and_config", "global_strict")


def _load_file(path: str) -> list[Invariant]:
    import yaml
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        raise ValueError(f"malformed invariants file {path}: {e}") from e
    data = data or {}
    invariants = []
    for i, item in enumerate(data.get("invariants", []) or []):
        inv_id = str(item.get("id", f"repo-{i}"))
        raw_scope = item.get("target_scope")
        scope = "global_strict" if raw_scope is None else str(raw_scope).strip().lower()
        if scope not in VALID_TARGET_SCOPES:
            raise ValueError(
                f"invalid target_scope '{raw_scope}' in invariant '{inv_id}'; "
                f"must be one of {VALID_TARGET_SCOPES}"
            )
        allowlist = item.get("test_allowlist_patterns")
        if allowlist is not None:
            if scope != "global_strict":
                raise ValueError(
                    f"test_allowlist_patterns is only valid for target_scope 'global_strict' "
                    f"(found in invariant '{inv_id}' with scope '{scope}')"
                )
            if not isinstance(allowlist, (list, tuple)):
                raise ValueError(
                    f"test_allowlist_patterns in invariant '{inv_id}' must be a list of strings"
                )
            allowlist_tuple = tuple(str(x) for x in allowlist)
        else:
            allowlist_tuple = ()

        invariants.append(Invariant(
            invariant_id=inv_id,
            rule=str(item.get("rule", "")),
            compiled_query=str(item.get("query", "")),
            blocking=bool(item.get("blocking", True)),
            target_scope=scope,
            test_allowlist_patterns=allowlist_tuple,
        ))
    return invariants
