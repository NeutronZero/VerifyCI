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


def find_deletion_hunks(diff: str | None) -> list[tuple[int, str]]:
    """Return (hunk_start_line, removed_text) for each hunk that removes
    lines without adding any — a `-` line with no paired `+` in the same
    hunk. Modifications (`-`/`+` pairs) are not deletions. Content-level
    removal verification is V1.1; this lets the verifier honestly admit it
    cannot confirm removals rather than returning PASS."""
    if not diff:
        return []
    hunks = []
    in_hunk = False
    has_minus = has_plus = False
    hunk_start = 0
    removed: list[str] = []
    for i, line in enumerate(str(diff).splitlines(), 1):
        if line.startswith("@@"):
            if in_hunk and has_minus and not has_plus:
                hunks.append((hunk_start, "\n".join(removed)))
            in_hunk, has_minus, has_plus, removed = True, False, False, []
            hunk_start = i
        elif in_hunk:
            if line.startswith("-") and not line.startswith("---"):
                has_minus = True
                removed.append(line[1:])
            elif line.startswith("+"):
                has_plus = True
    if in_hunk and has_minus and not has_plus:
        hunks.append((hunk_start, "\n".join(removed)))
    return hunks


def find_ambiguous_files(files: list[str], entities: list) -> dict[str, list[str]]:
    """Diff file -> distinct stored paths it matched, when more than one.

    Suffix matching lets an old-layout path ground against a moved file —
    sometimes right, sometimes a same-named coincidence (`utils.py::load`
    in two packages). Callers surface this so a suffix-grounded PASS is
    visibly weaker than an exact-path one. Exact-only matches are never
    ambiguous.
    """
    wanted = {normalize_path(f) for f in files}
    hits: dict[str, set[str]] = {}
    for entity in entities:
        epath = normalize_path(getattr(entity, "file_path", ""))
        if not epath:
            continue
        for f in wanted:
            if epath == f:
                hits.setdefault(f, set()).add(epath)
            elif epath.endswith("/" + f) or f.endswith("/" + epath):
                hits.setdefault(f, set()).add(epath)
    return {f: sorted(paths) for f, paths in hits.items() if len(paths) > 1}
