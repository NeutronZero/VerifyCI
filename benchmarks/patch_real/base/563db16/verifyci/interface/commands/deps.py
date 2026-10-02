from pathlib import Path

from verifyci.ingestion.dependency import DEPENDENCY_FILES, extract_dependencies


def run_deps(path: str = ".") -> dict:
    repo = Path(path)
    result: dict[str, list] = {}
    for manifest, ecosystem in DEPENDENCY_FILES.items():
        for file in repo.rglob(manifest):
            if ".verifyci" in file.parts:
                continue
            edges = extract_dependencies(file.name, file.read_text(errors="replace"))
            result[str(file)] = [
                {"package": e.metadata.get("package"), "version": e.metadata.get("version"), "ecosystem": ecosystem}
                for e in edges
            ]
    return result
