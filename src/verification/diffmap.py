"""Map a unified diff onto graph entities.

Files named on either side of the diff (``+++`` first, then ``---`` for
pure deletions/renames, `/dev/null` excluded) can seed verification. A diff
that names no files, or only files absent from the graph, grounds nothing
and must yield ``inconclusive`` — never ``pass``.
"""

def parse_diff_files(diff: str | None) -> list[str]:
    if not diff:
        return []
    new_side, old_side = [], []
    for line in str(diff).splitlines():
        if line.startswith("+++ "):
            path = _clean(line[4:])
            if path is not None:
                new_side.append(path)
        elif line.startswith("--- "):
            path = _clean(line[4:])
            if path is not None:
                old_side.append(path)
    ordered = []
    for f in new_side + [p for p in old_side if p not in new_side]:
        if f not in ordered:
            ordered.append(f)
    return ordered


def _clean(fragment: str) -> str | None:
    path = fragment.strip().split("\t")[0].strip().strip('"')
    if path in ("-", "/dev/null"):
        return None
    return _strip_prefix(path)


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
