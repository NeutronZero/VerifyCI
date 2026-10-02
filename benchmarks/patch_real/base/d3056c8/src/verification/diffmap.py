"""Map a unified diff onto graph entities.

Files named on either side of the diff (``+++`` first, then ``---`` for
pure deletions/renames, `/dev/null` excluded) can seed verification. A diff
that names no files, or only files absent from the graph, grounds nothing
and must yield ``inconclusive`` — never ``pass``.

Header parsing is hunk-aware: a body line such as ``--- comment`` (a
removed ``-- comment`` line) or ``+++ i`` (an added ``++ i`` line) is diff
*content*, never a file header. Only ``---``/``+++`` lines outside a hunk
body name files.
"""

_HUNK_BODY_PREFIXES = (" ", "+", "-", "\\")


def _diff_lines(diff: str | None) -> list[str]:
    """Split diff text the way the format delimits it: on `\n` only.

    `str.splitlines()` also splits on `\x0b\x0c\u2028\u2029`, so a form
    feed inside a removed line's content became two body lines and the
    halves mismatched stored snippets as "fabricated". A single trailing
    `\r` per line is stripped to preserve `\r\n` behavior.
    """
    if not diff:
        return []
    lines = str(diff).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _is_header(line: str, marker: str) -> bool:
    return line.startswith(marker) and line[len(marker):len(marker) + 1] in (" ", "\t")


def parse_diff_files(diff: str | None) -> list[str]:
    if not diff:
        return []
    new_side, old_side = [], []
    in_hunk = False
    for line in _diff_lines(diff):
        if line.startswith("diff --git "):
            in_hunk = False
            continue
        if in_hunk and (line.startswith(_HUNK_BODY_PREFIXES) or line == ""):
            continue
        in_hunk = False
        if line.startswith("@@"):
            in_hunk = True
        elif _is_header(line, "+++"):
            path = _clean(line[4:])
            if path is not None:
                new_side.append(path)
        elif _is_header(line, "---"):
            path = _clean(line[4:])
            if path is not None:
                old_side.append(path)
    ordered = []
    for f in new_side + [p for p in old_side if p not in new_side]:
        if f not in ordered:
            ordered.append(f)
    return ordered


def iter_added_lines(diff: str | None) -> list[tuple[str | None, str]]:
    """Every added line as (file_or_None, content).

    Lines inside ``@@`` hunks attribute to the current file; added lines
    outside any hunk (malformed diff, or preamble before the first
    ``diff --git``) attribute to the file whose headers were seen so far,
    or ``None`` when no file is known. Callers checking diff content must
    use this — scanning only hunk bodies lets added lines smuggled outside
    ``@@`` regions bypass every content check.
    """
    out: list[tuple[str | None, str]] = []
    if not diff:
        return out
    current: str | None = None
    in_hunk = False
    for line in _diff_lines(diff):
        if line.startswith("diff --git "):
            current, in_hunk = None, False
            continue
        if in_hunk and (line.startswith(_HUNK_BODY_PREFIXES) or line == ""):
            if line.startswith("+"):
                out.append((current, line[1:]))
            continue
        in_hunk = False
        if line.startswith("@@"):
            in_hunk = True
        elif _is_header(line, "+++"):
            path = _clean(line[4:])
            current = path
        elif _is_header(line, "---"):
            continue
        elif line.startswith("+"):
            out.append((current, line[1:]))
    return out


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
    # Strip leading "./" segments only. str.lstrip("./") is wrong here: it
    # strips every leading "." and "/" character, so ".verifyci/x" became
    # "verifyci/x" and "../etc/passwd" became "etc/passwd" — silently
    # widening the suffix-match groundable set toward false PASSes.
    p = str(path).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


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
    """Return (hunk_start_line, removed_text) for each hunk with a net
    removal — more `-` lines than `+` lines.

    A single `+` line no longer clears a hunk: deleting a function and
    adding one blank line is a net deletion, not a modification, and
    previously verified as PASS. Balanced `-`/`+` pairs (true
    modifications) are still not deletions. Residual gap, stated plainly:
    an attacker adding at least as many junk lines as removed lines still
    evades this tripwire; content-level removal verification is V1.1."""
    if not diff:
        return []
    hunks = []
    in_hunk = False
    hunk_start = 0
    minus = plus = 0
    removed: list[str] = []
    for i, line in enumerate(_diff_lines(diff), 1):
        if line.startswith("diff --git "):
            if in_hunk and minus > plus:
                hunks.append((hunk_start, "\n".join(removed)))
            in_hunk, minus, plus, removed = False, 0, 0, []
            continue
        if in_hunk and (line.startswith(_HUNK_BODY_PREFIXES) or line == ""):
            if line.startswith("-"):
                minus += 1
                removed.append(line[1:])
            elif line.startswith("+"):
                plus += 1
            continue
        if in_hunk and minus > plus:
            hunks.append((hunk_start, "\n".join(removed)))
        in_hunk, minus, plus, removed = False, 0, 0, []
        if line.startswith("@@"):
            in_hunk, hunk_start = True, i
    if in_hunk and minus > plus:
        hunks.append((hunk_start, "\n".join(removed)))
    return hunks


def iter_hunks(diff: str | None) -> list:
    """Parse hunks as (file, old_start, old_count, new_start, new_count,
    body_lines). `file` is the current `+++` path (None before any
    header); body lines keep their ` `/`+`/`-` prefix. Header-only diffs
    yield nothing."""
    import re
    from dataclasses import dataclass

    @dataclass
    class _Hunk:
        file: str | None
        old_start: int
        old_count: int
        new_start: int
        new_count: int
        lines: list

    head_re = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    hunks: list = []
    current: str | None = None
    open_hunk: _Hunk | None = None

    def flush():
        nonlocal open_hunk
        if open_hunk is not None:
            hunks.append(open_hunk)
            open_hunk = None

    for line in (_diff_lines(diff) if diff else []):
        if line.startswith("diff --git "):
            flush()
            current = None
            continue
        m = head_re.match(line)
        if m:
            flush()
            open_hunk = _Hunk(current, int(m.group(1)), int(m.group(2) or 1),
                              int(m.group(3)), int(m.group(4) or 1), [])
            continue
        if open_hunk is not None:
            if line.startswith(_HUNK_BODY_PREFIXES) or line == "":
                open_hunk.lines.append(line)
                continue
            flush()
        if _is_header(line, "+++"):
            path = _clean(line[4:])
            current = path
    flush()
    return hunks


def seed_entities_for_diff(files: list[str], entities: list, diff: str | None) -> dict[str, list[str]]:
    """Changed file -> revision_entity_ids of entities the diff touches.

    Whole-file mapping narrowed by hunk anchors: an entity seeds blast
    measurement only if its line range contains a removed (old-side) line
    or a hunk's old-side anchor — the pre-change location of the edit.
    Seeding all 600 entities of a touched file made every connected diff
    report risk 1.0; anchoring recovers per-edit impact.

    Header-only diffs (no hunks: mode changes, whole-file deletes) fall
    back to whole-file mapping so they still ground. MODULE rows never
    seed: file existence is not code impact.
    """
    hunks = iter_hunks(diff)
    if not hunks:
        return map_files_to_entity_ids(files, entities)
    per_file: dict[str, set[int]] = {}
    for h in hunks:
        if h.file is None:
            continue
        touched = per_file.setdefault(h.file, set())
        old_ln = h.old_start
        for body in h.lines:
            if body.startswith("-"):
                touched.add(old_ln)
                old_ln += 1
            elif body.startswith("\\"):
                continue
            elif not body.startswith("+"):
                old_ln += 1
        # Pure additions move no old-side lines: anchor the hunk's
        # pre-change location (enclosing scope seeds the measurement).
        # old_start == 0 means "before the first line" (new file):
        # nothing in the graph can contain it, so it seeds nothing.
        if h.old_start > 0:
            touched.add(h.old_start)
    mapping: dict[str, list[str]] = {}
    wanted = {normalize_path(f) for f in files}
    for entity in entities:
        if not _is_seedable(entity):
            continue
        epath = normalize_path(getattr(entity, "file_path", ""))
        for f in wanted:
            if not (epath == f or epath.endswith("/" + f) or f.endswith("/" + epath)):
                continue
            lines = per_file.get(f)
            if lines is None:
                # File named but hunkless in a diff that has hunks
                # elsewhere (e.g. a mode change): whole-file fallback.
                mapping.setdefault(f, []).append(entity.revision_entity_id)
                continue
            start = getattr(entity, "line_start", 1) or 1
            end = getattr(entity, "line_end", start) or start
            if any(start <= ln <= end for ln in lines):
                mapping.setdefault(f, []).append(entity.revision_entity_id)
    return mapping


def _is_seedable(entity) -> bool:
    """Code entities seed impact measurement; MODULE rows do not."""
    t = getattr(entity, "type", None)
    if t is None:
        return True
    return str(getattr(t, "value", t)) != "MODULE"


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
