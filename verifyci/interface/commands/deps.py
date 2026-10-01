from pathlib import Path

from verifyci.ingestion.dependency import DEPENDENCY_FILES, extract_dependencies
from verifyci.ingestion.ignore import iter_repo_files


def run_deps(path: str = ".") -> dict:
    """Dependencies for a repo, using the same skip rules as ingestion.

    Uses `iter_repo_files` so a manifest under node_modules/, a
    virtualenv, `.git/`, or a `.verifyciignore`d path is excluded here
    exactly as it is during ingest (the two paths used to disagree).
    """
    repo = Path(path)
    result: dict[str, list] = {}
    errors: list[str] = []
    for file in iter_repo_files(repo):
        if file.name not in DEPENDENCY_FILES:
            continue
        ecosystem = DEPENDENCY_FILES[file.name]
        edges = extract_dependencies(
            file.name,
            # Same deterministic decode as ingest (utf-8-sig, BOM-safe):
            # the two discovery paths must agree on manifest bytes or
            # deps and the graph disagree about what the manifest says.
            file.read_text(encoding="utf-8-sig", errors="replace"),
            errors=errors)
        result[file.relative_to(repo).as_posix()] = [
            {"package": e.metadata.get("package"), "version": e.metadata.get("version"), "ecosystem": ecosystem}
            for e in edges
        ]
    if errors:
        # A corrupt manifest here is SBOM loss with no record; report it.
        result["manifest_errors"] = errors
    return result