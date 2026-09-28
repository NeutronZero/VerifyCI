"""Project invariant configuration: repo-local, default-on.

Invariants are project-specific facts, so they live with the code: a
`invariants.yaml` next to the DB (i.e. `<repo>/.verifyci/invariants.yaml`).
`run_verify` loads it by default — not an opt-in flag — and its rules run
*in addition to* the built-ins, so the common path can never silently
revert to the hardcoded pair.

Flat list only (`forbid_call:`, `forbid_import:`, `secrets_scan`,
`provenance_check`). Scope-conditional rules wait until a flat list is
proven insufficient (Principle 6).

```yaml
invariants:
  - id: no-sync-in-sansio
    rule: sansio must not import sync flask modules
    query: "forbid_import:..config"
    blocking: true
```
"""
import os

from src.contracts.verification_ir import Invariant
from src.verification.defaults import default_invariants

FILENAME = "invariants.yaml"


def repo_invariants_path(db_path: str | None) -> str | None:
    if not db_path:
        return None
    candidate = os.path.join(os.path.dirname(os.path.abspath(db_path)), FILENAME)
    return candidate if os.path.exists(candidate) else None


def load_repo_invariants(db_path: str | None = None, path: str | None = None) -> list[Invariant]:
    """Built-ins plus repo-local rules. Missing file == built-ins only."""
    resolved = path or repo_invariants_path(db_path)
    if not resolved:
        return default_invariants()
    return default_invariants() + _load_file(resolved)


def _load_file(path: str) -> list[Invariant]:
    import yaml
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    invariants = []
    for i, item in enumerate(data.get("invariants", []) or []):
        invariants.append(Invariant(
            invariant_id=str(item.get("id", f"repo-{i}")),
            rule=str(item.get("rule", "")),
            compiled_query=str(item.get("query", "")),
            blocking=bool(item.get("blocking", True)),
        ))
    return invariants
