from pathlib import Path


def resolve_db(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    local = Path(".verifyci") / "verifyci.db"
    if local.exists():
        return str(local)
    return str(Path("storage") / "verifyci.db")
