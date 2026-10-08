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


VALID_TARGET_SCOPES = ("code_core", "code_and_config", "global_strict")


def is_policy_file(path: str) -> bool:
    """True if path points to a gate configuration file."""
    if not path:
        return False
    p = path.replace("\\", "/").strip("/")
    parts = p.split("/")
    fname = parts[-1]
    if fname in (FILENAME, "invariants.yml", WAIVERS_FILENAME, "waivers.yml", "policy.yaml", "policy.yml"):
        return len(parts) == 1 or parts[-2] == ".verifyci" or ".verifyci" in parts
    return False


def _reverse_patch_text(head_text: str, hunks: list) -> str:
    lines = head_text.splitlines(keepends=True)
    for h in sorted(hunks, key=lambda x: x.new_start, reverse=True):
        new_start = max(0, h.new_start - 1)
        new_count = h.new_count
        old_lines = []
        for line in h.lines:
            if line.startswith("-") or line.startswith(" "):
                old_lines.append(line[1:] + ("\n" if not line[1:].endswith("\n") else ""))
        lines[new_start : new_start + new_count] = old_lines
    return "".join(lines)


def _target_variants(target_path: str) -> set[str]:
    """Path variants identifying a policy file without basename-only matching."""
    target_norm = target_path.replace("\\", "/").strip("/")
    variants = {target_norm}
    try:
        rel = os.path.relpath(target_path, os.getcwd()).replace("\\", "/").strip("/")
        if rel:
            variants.add(rel)
    except ValueError:
        pass
    # Preserve internal directory segments (not basename-only matching).
    parts = [part for part in target_norm.split("/") if part]
    if ".verifyci" in parts:
        i = parts.index(".verifyci")
        variants.add("/".join(parts[i:]))
    return {v for v in variants if v}


def _find_policy_diff(target_path: str, diff: str):
    """Return the diff entry touching target_path, or None when untouched.

    Distinguishes "policy file not in diff" (caller should use the live repo
    file) from "policy file in diff but base unrecoverable" (caller must fail
    closed and never fall back to the worktree file).
    """
    from verifyci.verification.diffmap import parse_unified_diff
    variants = _target_variants(target_path)
    target_base = target_path.replace("\\", "/").split("/")[-1]
    for f in parse_unified_diff(diff):
        for p in (f.old_path, f.new_path):
            if not p:
                continue
            p_norm = p.replace("\\", "/").strip("/")
            if any(
                p_norm == variant
                or p_norm.endswith("/" + variant)
                or variant.endswith("/" + p_norm)
                for variant in variants
            ):
                return f
            # Same policy filename inside a `.verifyci/` directory is the
            # canonical policy location even when the resolved target path
            # carries no `.verifyci` segment (e.g. a bare-db layout). A bare
            # same-basename file elsewhere (`other/invariants.yaml`) never
            # matches: basename-only matching stays removed.
            p_parts = [part for part in p_norm.split("/") if part]
            if (
                p_parts
                and p_parts[-1] == target_base
                and ".verifyci" in p_parts[:-1]
            ):
                return f
    return None


def extract_base_file_content(target_path: str, diff: str) -> str | None:
    """Extract or reconstruct the base (pre-PR) version of a policy file."""
    from verifyci.verification.diffmap import parse_unified_diff  # noqa: F401 (kept for symmetry)
    matching_diff = _find_policy_diff(target_path, diff)
    if not matching_diff or not matching_diff.hunks:
        return None

    # Base ref via git if available
    base_ref = os.environ.get("VERIFYCI_BASE_REF", os.environ.get("GITHUB_BASE_REF", ""))
    if base_ref:
        import subprocess
        try:
            res = subprocess.run(["git", "show", f"{base_ref}:{target_path}"],
                                 capture_output=True, text=True, check=True)
            return res.stdout
        except Exception:
            pass

    # If file was deleted or not on disk, reconstruct base from hunk old lines
    old_lines = []
    for h in matching_diff.hunks:
        for line in h.lines:
            if line.startswith("-") or line.startswith(" "):
                old_lines.append(line[1:] + ("\n" if not line[1:].endswith("\n") else ""))
    return "".join(old_lines) if old_lines else None


def _parse_waivers_data(data: dict, path: str) -> list[SignedIntentWaiver]:
    if not isinstance(data, dict):
        raise ValueError(f"malformed waivers file {path}: top-level must be a mapping")
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


def _load_waivers_file(path: str) -> list[SignedIntentWaiver]:
    import yaml
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        raise ValueError(f"malformed waivers file {path}: {e}") from e
    return _parse_waivers_data(data or {}, path)


def load_trusted_base_waivers(db_path: str | None = None, path: str | None = None,
                              diff: str | None = None) -> list[SignedIntentWaiver]:
    """Load trusted base waivers. If diff modifies waivers, reconstruct base waivers."""
    resolved = path or repo_waivers_path(db_path)
    target = resolved or (os.path.join(os.path.dirname(os.path.abspath(db_path)), WAIVERS_FILENAME) if db_path else WAIVERS_FILENAME)
    if diff:
        if _find_policy_diff(target, diff) is None:
            # Policy file untouched by this diff: the live repo file is the
            # trusted base. Fail-closed only applies when the diff modifies
            # gate configuration but the base cannot be reconstructed.
            return load_repo_waivers(db_path, path)
        base_content = extract_base_file_content(target, diff)
        if base_content is not None:
            import yaml
            try:
                data = yaml.safe_load(base_content) or {}
                if isinstance(data, dict):
                    return _parse_waivers_data(data, target)
            except Exception:
                return []
        # The diff changed gate configuration but the trusted base could not
        # be reconstructed. Never fall back to the current worktree file.
        return []
    return load_repo_waivers(db_path, path)


def _parse_invariants_data(data: dict, path: str) -> list[Invariant]:
    if not isinstance(data, dict):
        raise ValueError(f"malformed invariants file {path}: top-level must be a mapping")
    invariants = []
    for i, item in enumerate(data.get("invariants", []) or []):
        if not isinstance(item, dict):
            raise ValueError(f"invariant entry #{i} in {path} must be a mapping")
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


def _load_file(path: str) -> list[Invariant]:
    import yaml
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        raise ValueError(f"malformed invariants file {path}: {e}") from e
    return _parse_invariants_data(data or {}, path)


def load_trusted_base_invariants(db_path: str | None = None, path: str | None = None,
                                 diff: str | None = None) -> list[Invariant]:
    """Load trusted base invariants. If diff modifies invariants, reconstruct base invariants."""
    resolved = path or repo_invariants_path(db_path)
    target = resolved or (os.path.join(os.path.dirname(os.path.abspath(db_path)), FILENAME) if db_path else FILENAME)
    if diff:
        if _find_policy_diff(target, diff) is None:
            # Policy file untouched by this diff: the live repo file is the
            # trusted base. Fail-closed only applies when the diff modifies
            # gate configuration but the base cannot be reconstructed.
            return load_repo_invariants(db_path, path)
        base_content = extract_base_file_content(target, diff)
        if base_content is not None:
            import yaml
            try:
                data = yaml.safe_load(base_content) or {}
                if isinstance(data, dict):
                    return default_invariants() + _parse_invariants_data(data, target)
            except Exception:
                return default_invariants()
        # Configuration was modified but no trustworthy base could be
        # reconstructed. Keep only immutable built-ins; never load HEAD.
        return default_invariants()
    return load_repo_invariants(db_path, path)
