from pathlib import Path


def resolve_db(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    local = Path(".verifyci") / "verifyci.db"
    if local.exists():
        return str(local)
    return str(Path("storage") / "verifyci.db")


def resolve_repository(db_path: str | None) -> str | None:
    """Repository id implied by a DB path, or None.

    Ingest writes `<repo>/.verifyci/verifyci.db` with
    `repository_id=repo.name`, so a DB under `.verifyci` names its own
    repo (innermost `.verifyci` wins for nested checkouts). Anything
    else — custom `--db` paths, shared files — implies nothing, and
    callers fall back to the unscoped global lookup.
    """
    if not db_path:
        return None
    parts = Path(db_path).as_posix().split("/")
    if ".verifyci" not in parts:
        return None
    idx = len(parts) - 1 - parts[::-1].index(".verifyci")
    return parts[idx - 1] if idx > 0 else None
