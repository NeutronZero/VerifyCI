"""Map a unified diff onto graph entities.

Only files listed in the diff (``+++`` side) can seed verification. A diff
that names no files, or only files absent from the graph, grounds nothing
and must yield ``inconclusive`` — never ``pass``.
"""
import re


def parse_diff_files(diff: str | None) -> list[str]:
    if not diff:
        return []
    files = []
    for line in str(diff).splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip().split("\t")[0].strip().strip('"')
            if path in ("-", "/dev/null"):
                continue
            files.append(_strip_prefix(path))
    seen = set()
    ordered = []
    for f in files:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered


def _strip_prefix(path: str) -> str:
    for prefix in ("b/", "a/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def normalize_path(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def map_files_to_entity_ids(files: list[str], entities: list) -> dict[str, list[str]]:
    """Changed file -> revision_entity_ids of entities declared in it."""
    wanted = {normalize_path(f) for f in files}
    mapping: dict[str, list[str]] = {}
    for entity in entities:
        epath = normalize_path(getattr(entity, "file_path", ""))
        for f in wanted:
            if epath == f or epath.endswith("/" + f) or f.endswith("/" + epath):
                mapping.setdefault(f, []).append(entity.revision_entity_id)
    return mapping
