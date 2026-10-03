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
from dataclasses import dataclass, field
from enum import Enum

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


# --------------------------------------------------------------------------
# Canonical unified-diff parser (A4). One authoritative interpretation.
#
# Six earlier entry points (parse_diff_files, iter_added_lines[_with_lineno],
# unattributed_removed_lines, find_deletion_hunks, iter_hunks) each carried
# their own state machine and each sniffed hunk termination by line prefix
# rather than the declared `@@ -a,b +c,d @@` counts. That shared root cause
# produced the demonstrated defects: a classic (non-git) two-file diff lost
# its second file (the `--- two.py`/`+++ two.py` headers were swallowed as
# hunk body and `++ two.py` leaked into the added lines); binary-only and
# mode-only changes named no file at all and silently vanished from
# verification; a mixed text+binary diff verified the text half while the
# binary half disappeared. Every one-sided divergence is now read once, from
# the declared counts, and the six functions below are thin projections of
# parse_unified_diff's output.
#
# Grounding status is explicit and never optimistic: a file the diff names
# but whose content is not text (binary) or whose change is metadata-only
# (mode) is reported with grounding_status so callers route it to
# inconclusive rather than let it disappear. Ambiguous suffix-only paths are
# left to find_ambiguous_files (unchanged); nothing here manufactures a PASS.
# --------------------------------------------------------------------------

class GroundingStatus(Enum):
    TEXT = "text"          # has hunks with line-level content
    BINARY = "binary"      # "Binary files ... differ" / "GIT binary patch"
    MODE_ONLY = "mode_only"  # old mode/new mode, no content hunks
    EMPTY = "empty"        # named but produced no hunk/content (e.g. header-only)


@dataclass
class Hunk:
    file: str | None
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list = field(default_factory=list)
    approximate: bool = False


@dataclass
class FileDiff:
    old_path: str | None
    new_path: str | None
    hunks: list = field(default_factory=list)
    binary: bool = False
    mode_only: bool = False
    renamed: bool = False
    copied: bool = False
    # Index of the `diff --git`/`diff --cc` line that opened this block
    # (None for classic header-only blocks). Reconstruction maps each git
    # line to the block it opened 1:1 instead of zipping two
    # independently-built lists (a preamble entry used to shift every
    # later block onto the wrong paths).
    git_index: int | None = None
    # `+`/`-` lines seen outside any hunk for this file (git mode/index
    # regions, hand-edited diffs). Attributed to the file, counted nowhere.
    stray_added: list = field(default_factory=list)
    stray_removed: list = field(default_factory=list)

    @property
    def path(self) -> str | None:
        return self.new_path if self.new_path is not None else self.old_path

    @property
    def grounding_status(self) -> GroundingStatus:
        if self.binary:
            return GroundingStatus.BINARY
        if self.hunks:
            return GroundingStatus.TEXT
        if self.mode_only:
            return GroundingStatus.MODE_ONLY
        return GroundingStatus.EMPTY


_BIN_RE = re.compile(r"^Binary files .* and .* differ")
_DIFF_GIT_RE = re.compile(r"^diff --git ")
_DIFF_CC_RE = re.compile(r"^diff --cc[ ]")


def _split_git_paths(line: str) -> tuple[str | None, str | None]:
    """Best-effort (old, new) from a `diff --git a/X b/Y` line. Used only
    as a fallback when no ---/+++ header is present (mode-only/binary).
    Git quotes/escapes paths with spaces when they differ from the a/b
    defaults; the header path (strip_prefix) remains authoritative.
    `--no-prefix` (and mnemonic prefixes) carry no ` b/` marker: split
    the remainder on whitespace then, still best-effort."""
    rest = line[len("diff --git "):].strip()
    if " b/" in rest and not rest.startswith('"'):
        head, _, tail = rest.partition(" b/")
        old = head[2:] if head.startswith("a/") else head
        return _strip_prefix("a/" + old) if old else None, _strip_prefix("b/" + tail)
    import shlex
    try:
        parts = shlex.split(rest)
    except Exception:
        parts = rest.split()
    if len(parts) == 2:
        return _strip_prefix(parts[0]), _strip_prefix(parts[1])
    return None, None


def _new_file_ahead(lines: list[str], idx: int) -> bool:
    """True when a header-like `---` line opens a NEW file block rather
    than a removed `-- ...` content line: it is followed by its `+++`
    mate (itself followed by a hunk or another file block — never more
    body, never end of input: a header pair ending the input is
    content-shaped, and breaking there would split exact-count diffs
    whose removed `-- x` / added `++ y` lines are the whole hunk), or
    directly by a new `diff --git/--cc` block. Hand-written/LLM diffs
    with overstated hunk counts absorb the next file's headers as body
    without this; exact-count diffs never satisfy it with sides
    remaining, so valid content is untouched."""
    if not _is_header(lines[idx], "---"):
        return False
    nxt = lines[idx + 1] if idx + 1 < len(lines) else ""
    if nxt.startswith("diff --git ") or nxt.startswith("diff --cc"):
        return True
    if not _is_header(nxt, "+++"):
        return False
    nxt2 = lines[idx + 2] if idx + 2 < len(lines) else ""
    return (_HEAD_RE.match(nxt2) is not None or nxt2.startswith("@@")
            or nxt2.startswith("diff --git ") or nxt2.startswith("diff --cc"))


def _is_boundary(line: str) -> bool:
    """A line that ends a hunk body regardless of remaining declared
    counts: a new file's header or a new hunk. A bare `---`/`+++` is only
    a boundary when it looks like a file header (space-separated path),
    never when it is diff *content* (`--- comment` as a removed line)."""
    return (line.startswith("diff --git ") or line.startswith("diff --cc")
            or _HEAD_RE.match(line) is not None
            or _COMBINED_RE.match(line) is not None
            or line.startswith("@@@"))


def _header_path(line: str, marker: str) -> str | None:
    if not _is_header(line, marker):
        return None
    return _clean(line[len(marker):])


def parse_unified_diff(diff: str | None) -> list[FileDiff]:
    lines = _diff_lines(diff)
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    pair_complete = False   # cur has seen both --- and +++ header lines
    preamble = FileDiff(None, None)

    def _file() -> FileDiff:
        nonlocal cur
        if cur is None:
            cur = FileDiff(None, None)
            files.append(cur)
        return cur

    idx = 0
    while idx < len(lines):
        line = lines[idx]
        # --- file-level metadata ---------------------------------------
        if _DIFF_GIT_RE.match(line) or _DIFF_CC_RE.match(line):
            # A new per-file block starts here, period — even without
            # headers (mode-only/binary blocks carry only the --git line;
            # _reconstruct_git_paths back-fills the path). The block
            # records which git line opened it so reconstruction cannot
            # misalign when preamble or header-only entries intervene.
            cur = FileDiff(None, None, git_index=idx)
            files.append(cur)
            pair_complete = False
            idx += 1
            continue
        if line.startswith("new file mode") or line.startswith("deleted file mode"):
            _file()
            idx += 1
            continue
        if line.startswith("old mode") or line.startswith("new mode"):
            _file().mode_only = True
            idx += 1
            continue
        if line.startswith("rename from "):
            p = _clean(line[len("rename from "):])
            if p is not None:
                _file().old_path = p
                _file().renamed = True
            idx += 1
            continue
        if line.startswith("rename to "):
            p = _clean(line[len("rename to "):])
            if p is not None:
                _file().new_path = p
                _file().renamed = True
            idx += 1
            continue
        if line.startswith("copy from "):
            p = _clean(line[len("copy from "):])
            if p is not None:
                _file().old_path = p
                _file().copied = True
            idx += 1
            continue
        if line.startswith("copy to "):
            p = _clean(line[len("copy to "):])
            if p is not None:
                _file().new_path = p
                _file().copied = True
            idx += 1
            continue
        if line.startswith(("similarity index", "dissimilarity index", "index ",
                            "copy ", "rename ")):
            _file()
            idx += 1
            continue
        if _BIN_RE.match(line) or line.startswith("GIT binary patch"):
            _file().binary = True
            idx += 1
            continue
        # --- headers define the file's paths. A second complete ---/+++
        # pair outside a hunk opens a NEW file block (classic unified
        # diffs carry no `diff --git` line to split on — that swallow was
        # the h-classic-twofile defect). ---
        if _is_header(line, "---"):
            if pair_complete and cur is not None:
                cur, pair_complete = None, False
            f = _file()
            p = _header_path(line, "---")
            if p is not None:
                f.old_path = p
            pair_complete = False
            idx += 1
            continue
        if _is_header(line, "+++"):
            f = _file()
            p = _header_path(line, "+++")
            if p is not None:
                f.new_path = p
            pair_complete = True
            idx += 1
            continue
        # --- hunk: consume exactly the declared counts -----------------
        # A body line MUST start with one of " +-\\" or be empty; anything
        # else ends the hunk early (git truncation guard). `\ No newline`
        # markers are body lines that consume neither side's counts.
        head = _HEAD_RE.match(line)
        if head:
            f = _file()
            old_start = int(head.group(1))
            old_count = int(head.group(2) if head.group(2) is not None else 1)
            new_start = int(head.group(3))
            new_count = int(head.group(4) if head.group(4) is not None else 1)
            h = Hunk(f.path, old_start, old_count, new_start, new_count, [])
            idx += 1
            old_rem, new_rem = old_count, new_count
            while idx < len(lines) and (old_rem > 0 or new_rem > 0):
                b = lines[idx]
                if _is_boundary(b):
                    break
                if _new_file_ahead(lines, idx):
                    # Overstated counts ran past the hunk into the next
                    # file's headers: stop and let the `---` line open a
                    # NEW block (cur=None) instead of corrupting this
                    # file's paths with content-shaped headers.
                    cur, pair_complete = None, False
                    break
                if b.startswith("\\"):
                    h.lines.append(b)
                    idx += 1
                    continue
                if b and b[0] not in " +-\\":
                    break  # not a valid body line: stop, don't absorb
                if b.startswith("+"):
                    if new_rem <= 0:
                        break  # overstated counts: stop, don't absorb
                    new_rem -= 1
                elif b.startswith("-"):
                    if old_rem <= 0:
                        break
                    old_rem -= 1
                else:
                    if old_rem <= 0 or new_rem <= 0:
                        break
                    old_rem -= 1
                    new_rem -= 1
                # An empty line is context with the space stripped
                # (git emits " " as ""); it consumes both counts.
                h.lines.append(b if b != "" else " ")
                idx += 1
            f.hunks.append(h)
            continue
        comb = _COMBINED_RE.match(line)
        if comb or line.startswith("@@"):
            # combined (@@@) or malformed @@: greedy, approximate — one
            # side of a merge diff has no single coherent count model, so
            # consumers treat its lines as unverified (removal.py's
            # approximate branch); unchanged semantics.
            f = _file()
            try:
                om = re.search(r"-(\d+)", line)
                nms = re.findall(r"\+(\d+)", line)
                old_start = int(om.group(1)) if om else 0
                new_start = int(nms[-1]) if nms else 0
            except Exception:
                old_start = new_start = 0
            h = Hunk(f.path, old_start, 1, new_start, 1, [], approximate=True)
            idx += 1
            while idx < len(lines):
                b = lines[idx]
                if _is_boundary(b):
                    break
                if b.startswith(_HUNK_BODY_PREFIXES) or b == "":
                    h.lines.append(b)
                    idx += 1
                    continue
                if h.approximate and b.lstrip() != "":
                    h.lines.append(b)
                    idx += 1
                    continue
                break
            f.hunks.append(h)
            continue
        # --- stray +/- outside any hunk (never discarded) --------------
        if line == "--" or line == "-- ":
            # format-patch signature separator: end-of-patch marker, not
            # a removed `--` line (real removals live inside hunks).
            # Without this every format-patch input trips the removal
            # tripwire and declines to INCONCLUSIVE on its signature.
            # Mailbox preamble `+`/`-` lines stay scanned (fail-closed:
            # pinned preamble-secret behavior), only the separator is
            # structurally recognizable as non-content.
            idx += 1
            continue
        if line.startswith("+"):
            (_file() if cur is not None else preamble).stray_added.append(line[1:])
            idx += 1
            continue
        if line.startswith("-"):
            (_file() if cur is not None else preamble).stray_removed.append(line[1:])
            idx += 1
            continue
        idx += 1

    _reconstruct_git_paths(lines, files)
    if preamble.stray_added or preamble.stray_removed:
        files.insert(0, preamble)
    return files


def _reconstruct_git_paths(lines: list[str], files: list[FileDiff]) -> None:
    """A git block without ---/+++ headers (mode-only, binary-only) still
    names its file on the `diff --git` line: back-fill the path so the
    change reaches verification instead of disappearing. Keyed by the
    git line that opened each block — never by zipped positions, so a
    preamble or header-only entry cannot shift later blocks onto wrong
    paths."""
    for f in files:
        if f.path is not None or f.git_index is None:
            continue
        o, n = _split_git_paths(lines[f.git_index])
        f.old_path = f.old_path or o
        f.new_path = f.new_path or n


def parse_diff_files(diff: str | None) -> list[str]:
    """Files named by a diff, new-side first — a projection of the
    canonical parse. Binary and mode-only files are INCLUDED (a real
    change the diff names), so they can no longer vanish; whether each
    grounds to entities is the caller's (seed_entities_for_diff maps
    files that have graph entities; a binary with no entity contributes
    nothing but is not hidden)."""
    ordered: list[str] = []
    for f in parse_unified_diff(diff):
        for p in (f.new_path, f.old_path):
            if p is not None and p not in ordered:
                ordered.append(p)
    return ordered


def iter_added_lines(diff: str | None) -> list[tuple[str | None, str]]:
    """(file, content) for every added line, hunks then strays — the same
    order the old scanner produced (per file, in diff order)."""
    out: list[tuple[str | None, str]] = []
    for f in parse_unified_diff(diff):
        for h in f.hunks:
            for body in h.lines:
                if body.startswith("+"):
                    out.append((f.path, body[1:]))
        for line in f.stray_added:
            out.append((f.path, line))
    return out


def iter_added_lines_with_lineno(
        diff: str | None) -> list[tuple[str | None, int | None, str]]:
    """(file, new_lineno, content). lineno is None for strays and for the
    new-side start of an approximate hunk, matching the old scanner."""
    out: list[tuple[str | None, int | None, str]] = []
    for f in parse_unified_diff(diff):
        for h in f.hunks:
            new_ln = h.new_start
            for body in h.lines:
                if body.startswith("+"):
                    out.append((f.path, new_ln if h.approximate is False else None,
                                body[1:]))
                    new_ln += 1
                elif body.startswith("-") or body.startswith("\\"):
                    continue
                else:
                    new_ln += 1
        for line in f.stray_added:
            out.append((f.path, None, line))
    return out


def _clean(fragment: str) -> str | None:
    path = fragment.strip().split("\t")[0].strip().strip(chr(34))
    if path in ("-", "/dev/null"):
        return None
    return _strip_prefix(path)


def _strip_prefix(path: str) -> str:
    for prefix in ("b/", "a/", "b\\", "a\\"):
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
    """Removed (`-`) lines that belong to no hunk — git mode/index noise or
    hand-edited content. A projection of stray_removed; file headers and
    backslash markers are already consumed by the canonical parse, never
    strays."""
    out: list[str] = []
    for f in parse_unified_diff(diff):
        out.extend(f.stray_removed)
    return out


def find_deletion_hunks(diff: str | None) -> list[tuple[int, str]]:
    """Hunks that net-remove content (more `-` than `+`), plus any stray
    removal run — the removal-provenance tripwire. One-sided: a
    modification (`-x`/`+y`, counts equal) is NOT a deletion; a pure
    addition is not. `(start, text)` keeps the old tuple shape; only
    `text` and `len()` are consumed downstream, `start` is the grouping
    key. Approximate (combined `@@@`) hunks flag on any removal, matching
    the previous scanner's special case."""
    hunks: list[tuple[int, str]] = []
    for f in parse_unified_diff(diff):
        for h in f.hunks:
            if h.approximate:
                removed = [b.lstrip()[1:] if b.lstrip()[:1] in "-+" else b.lstrip()
                           for b in h.lines if b.lstrip().startswith("-")]
                if removed:
                    hunks.append((h.old_start, "\n".join(removed)))
                continue
            minus = [b[1:] for b in h.lines if b.startswith("-")]
            plus = sum(1 for b in h.lines if b.startswith("+"))
            if minus and len(minus) > plus:
                hunks.append((h.old_start, "\n".join(minus)))
        if f.stray_removed:
            hunks.append((0, "\n".join(f.stray_removed)))
    return hunks


def iter_hunks(diff: str | None) -> list:
    """Every hunk in file-then-diff order (fields: file, old_start,
    old_count, new_start, new_count, lines, approximate). Callers that
    want per-file grouping iterate parse_unified_diff directly."""
    out = []
    for f in parse_unified_diff(diff):
        for h in f.hunks:
            h.file = f.path
            out.append(h)
    return out


def diff_grounding_statuses(diff: str | None) -> dict[str, "GroundingStatus"]:
    """path -> grounding_status for every file the diff names. Binary and
    mode-only entries let decision points treat an uninspectable change as
    visible-but-ungroundable rather than absent."""
    statuses: dict[str, GroundingStatus] = {}
    for f in parse_unified_diff(diff):
        p = f.path
        if p is not None:
            statuses[normalize_path(p)] = f.grounding_status
    return statuses


def uninspectable_files(diff: str | None) -> list[str]:
    """Files the diff names whose content it does not carry (binary, or
    header-only with no hunks and no rename target). A verification that
    cannot read the change must not certify it: these force inconclusive
    rather than a PASS earned by the text-only siblings of a mixed diff.
    Hunk-less renames/copies are the same class: the diff carries no
    content for the move, so a same-named entity in the base graph must
    not ground a PASS for it."""
    out: list[str] = []
    for f in parse_unified_diff(diff):
        if f.binary:
            out.append(f.path)
        elif f.mode_only and not f.hunks and not f.stray_added and not f.stray_removed:
            out.append(f.path)
        elif (f.renamed or f.copied) and not f.hunks and not f.stray_added and not f.stray_removed:
            out.append(f.path)
    return [p for p in out if p is not None]


def changed_line_anchor_sets(diff: str | None) -> dict[str, list[set[int]]]:
    """Old-side anchors per changed LINE, by diff file path.

    A `-` line anchors its own old line. A `+` line anchors the
    insertion point: both sides (`old_ln`, `old_ln - 1`) for a pure
    insertion — text added between two old lines touches either side
    (the A2 tail-insertion geometry) — or the removed lines it
    replaces (`old_ln - 1`) when it directly follows `-` lines. The
    coverage veto reads these sets: a changed line is covered when ANY
    of its anchors sits inside an entity span, so a tail insertion at
    a function's last line stays covered while a module-constant edit
    (neither side inside any span) does not."""
    per_file: dict[str, list[set[int]]] = {}
    for h in iter_hunks(diff):
        if h.file is None:
            continue
        sets = per_file.setdefault(h.file, [])
        old_ln = h.old_start
        prev_minus = False
        for body in h.lines:
            if body.startswith("-"):
                sets.append({old_ln})
                old_ln += 1
                prev_minus = True
            elif body.startswith("\\"):
                continue
            elif body.startswith("+"):
                if prev_minus:
                    sets.append({old_ln - 1} if old_ln > 1 else {old_ln})
                else:
                    s = {old_ln}
                    if old_ln > 1:
                        s.add(old_ln - 1)
                    sets.append(s)
            else:
                old_ln += 1
                prev_minus = False
    return per_file


def changed_anchors_by_file(diff: str | None) -> dict[str, set[int]]:
    """Old-side line anchors each file's change touches, keyed by the
    diff's file path: the union of changed_line_anchor_sets plus each
    hunk's start line (conservative seeding blanket). The union keeps
    the frozen seeding geometry bit-identical (blast-corpus POSTFIX
    depends on it); the coverage veto reads the per-line sets
    directly, where a changed line is covered when ANY anchor lands
    in-span."""
    per_file: dict[str, set[int]] = {}
    for h in iter_hunks(diff):
        if h.file is None:
            continue
        touched = per_file.setdefault(h.file, set())
        norm_key = normalize_path(h.file)
        if norm_key != h.file:
            per_file[norm_key] = touched
        old_ln = h.old_start
        for body in h.lines:
            if body.startswith("-"):
                touched.add(old_ln)
                old_ln += 1
            elif body.startswith("\\"):
                continue
            elif body.startswith("+"):
                # Every insertion anchors BOTH sides (recall over
                # precision — the A2 tail-insertion geometry). This loop
                # is the frozen seeding geometry: do not "improve" it
                # here (blast-corpus POSTFIX depends on it bit for
                # bit); precise replacement semantics live in
                # changed_line_anchor_sets, which the veto reads.
                touched.add(old_ln)
                if old_ln > 1:
                    touched.add(old_ln - 1)
            else:
                old_ln += 1
        if h.old_start > 0:
            touched.add(h.old_start)
    return per_file


def seed_entities_for_diff(files: list[str], entities: list, diff: str | None) -> dict[str, list[str]]:
    hunks = iter_hunks(diff)
    if not hunks:
        return map_files_to_entity_ids(files, entities)
    per_file = changed_anchors_by_file(diff)
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
