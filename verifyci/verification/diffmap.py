"""Map a unified diff onto graph entities.

Files named on either side of the diff (``+++`` first, then ``---`` for
pure deletions/renames, `/dev/null` excluded) can seed verification. A diff
that names no files, or only files absent from the graph, grounds nothing
and must yield ``inconclusive`` - never ``pass``.

Header parsing is hunk-aware: a body line such as ``--- comment`` (a
removed ``-- comment`` line) or ``+++ i`` (an added ``++ i`` line) is diff
*content*, never a file header. Only ``---``/``+++`` lines outside a hunk
body name files.
"""
import re

_HUNK_BODY_PREFIXES = (" ", "+", "-", "\\")

_HEAD_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_COMBINED_RE = re.compile(r"^@@@ -\d+(?:,\d+)? .*\+(\d+)(?:,(\d+))? @@@")


def _diff_lines(diff: str | None) -> list[str]:
    if not diff:
        return []
    lines = str(diff).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _is_header(line: str, marker: str) -> bool:
    return line.startswith(marker) and line[len(marker):len(marker) + 1] in (" ", "\t")


def _is_git_file_header(line: str, marker: str) -> bool:
    if not _is_header(line, marker):
        return False
    rest = line[len(marker):].strip().strip(chr(34)).strip(chr(39))
    return (
        rest.startswith("a/")
        or rest.startswith("b/")
        or rest.startswith("/dev/null")
        or rest in ("-", "/dev/null")
    )


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
        elif line.startswith("rename to "):
            path = _clean(line[10:])
            if path is not None:
                new_side.append(path)
        elif line.startswith("rename from "):
            path = _clean(line[12:])
            if path is not None:
                old_side.append(path)
    ordered = []
    for f in new_side + [p for p in old_side if p not in new_side]:
        if f not in ordered:
            ordered.append(f)
    return ordered


def iter_added_lines(diff: str | None) -> list[tuple[str | None, str]]:
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
    path = fragment.strip().split("\t")[0].strip().strip(chr(34))
    if path in ("-", "/dev/null"):
        return None
    return _strip_prefix(path)


def _strip_prefix(path: str) -> str:
    for prefix in ("b/", "a/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def normalize_path(path: str) -> str:
    p = str(path).replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def map_files_to_entity_ids(files: list[str], entities: list) -> dict[str, list[str]]:
    wanted = {normalize_path(f) for f in files}
    mapping: dict[str, list[str]] = {}
    for entity in entities:
        epath = normalize_path(getattr(entity, "file_path", ""))
        for f in wanted:
            if epath == f or epath.endswith("/" + f) or f.endswith("/" + epath):
                mapping.setdefault(f, []).append(entity.revision_entity_id)
    return mapping


def unattributed_removed_lines(diff: str | None) -> list[str]:
    if not diff:
        return []
    out: list[str] = []
    in_hunk = False
    for line in _diff_lines(diff):
        if line.startswith("diff --git "):
            in_hunk = False
            continue
        if _HEAD_RE.match(line) or _COMBINED_RE.match(line) or line.startswith("@@@"):
            in_hunk = True
            continue
        if in_hunk:
            if line.startswith(_HUNK_BODY_PREFIXES) or line == "":
                continue
            in_hunk = False
        if _is_git_file_header(line, "---") or _is_git_file_header(line, "+++"):
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("-"):
            out.append(line[1:])
    return out


def find_deletion_hunks(diff: str | None) -> list[tuple[int, str]]:
    if not diff:
        return []
    hunks = []
    in_hunk = False
    hunk_combined = False
    hunk_start = 0
    minus = plus = 0
    removed: list[str] = []
    stray_start = 0
    stray_removed: list[str] = []
    for i, line in enumerate(_diff_lines(diff), 1):
        if line.startswith("diff --git "):
            if in_hunk and minus > plus or (hunk_combined and minus > 0):
                hunks.append((hunk_start, "\n".join(removed)))
            in_hunk, hunk_combined, minus, plus, removed = False, False, 0, 0, []
            continue
        if in_hunk and (line.startswith(_HUNK_BODY_PREFIXES) or line == ""
                        or (hunk_combined and line.lstrip() != "")):
            if hunk_combined:
                head2 = line[:2] if len(line) >= 2 else line
                if "-" in head2:
                    minus += 1
                    stripped = line.lstrip()
                    body = stripped[1:] if stripped.startswith(("-", "+")) else stripped
                    if body.startswith("-"):
                        body = body[1:]
                    removed.append(body)
                elif "+" in head2:
                    plus += 1
            else:
                if line.startswith("-"):
                    minus += 1
                    removed.append(line[1:])
                elif line.startswith("+"):
                    plus += 1
            continue
        if in_hunk and minus > plus or (hunk_combined and minus > 0):
            hunks.append((hunk_start, "\n".join(removed)))
        in_hunk, hunk_combined, minus, plus, removed = False, False, 0, 0, []
        if line.startswith("@@"):
            in_hunk, hunk_start = True, i
            hunk_combined = line.startswith("@@@")
            continue
        if _is_git_file_header(line, "---") or _is_git_file_header(line, "+++"):
            continue
        if line.startswith("\\"):
            continue
        if line.startswith("-"):
            if stray_start == 0:
                stray_start = i
            stray_removed.append(line[1:])
    if in_hunk and minus > plus or (hunk_combined and minus > 0):
        hunks.append((hunk_start, "\n".join(removed)))
    if stray_removed:
        hunks.append((stray_start or 0, "\n".join(stray_removed)))
    return hunks


def iter_hunks(diff: str | None) -> list:
    from dataclasses import dataclass

    @dataclass
    class _Hunk:
        file: str | None
        old_start: int
        old_count: int
        new_start: int
        new_count: int
        lines: list
        approximate: bool = False

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
        m = _HEAD_RE.match(line)
        if m:
            flush()
            open_hunk = _Hunk(current, int(m.group(1)), int(m.group(2) or 1),
                              int(m.group(3)), int(m.group(4) or 1), [])
            continue
        cm = _COMBINED_RE.match(line)
        if cm or (line.startswith("@@@") and line.rstrip().endswith("@@@")):
            flush()
            try:
                old_m = re.search(r"-(\d+)", line)
                new_ms = re.findall(r"\+(\d+)", line)
                old_start = int(old_m.group(1)) if old_m else 0
                new_start = int(new_ms[-1]) if new_ms else 0
            except Exception:
                old_start = new_start = 0
            open_hunk = _Hunk(current, old_start, 1, new_start, 1, [],
                              approximate=True)
            continue
        if open_hunk is not None:
            if line.startswith(_HUNK_BODY_PREFIXES) or line == "":
                open_hunk.lines.append(line)
                continue
            if getattr(open_hunk, "approximate", False) and line.lstrip() != "":
                open_hunk.lines.append(line)
                continue
            flush()
        if _is_header(line, "+++"):
            path = _clean(line[4:])
            current = path
    flush()
    return hunks


def seed_entities_for_diff(files: list[str], entities: list, diff: str | None) -> dict[str, list[str]]:
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
                mapping.setdefault(f, []).append(entity.revision_entity_id)
                continue
            start = getattr(entity, "line_start", 1) or 1
            end = getattr(entity, "line_end", start) or start
            if any(start <= ln <= end for ln in lines):
                mapping.setdefault(f, []).append(entity.revision_entity_id)
    return mapping


def _is_seedable(entity) -> bool:
    t = getattr(entity, "type", None)
    if t is None:
        return True
    return str(getattr(t, "value", t)) != "MODULE"


def find_ambiguous_files(files: list[str], entities: list) -> dict[str, list[str]]:
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