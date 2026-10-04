"""References introduced by a diff, extracted from added lines.

The base-revision graph cannot see new code, so graph-only invariant
checks (`forbid_call`, `forbid_import`) miss violations the diff itself
introduces (`+    eval(user_input)` passes silently). This module parses
each file's added lines as a fragment in that file's language and
collects bare call names and imported modules.

Two deliberate limits. Fragment parsing is best-effort: unbalanced
hunks yield ERROR nodes and whatever calls survive recovery are what
get checked — a recall gap, documented, same class as the secrets
scanner's. And matching is bare-name only (`eval(`, never `obj.eval(`):
stricter than the graph side (which is name-based throughout), because
added lines carry no receiver or scope information to disambiguate
with. Definitions (`def eval`) are function nodes, never call nodes,
so they cannot flag. Markdown/prose files are never parsed: added
prose mentioning `eval(` is not code.
"""
from verifyci.ingestion.extractor import (
    CALL_NODES,
    _extract_import_modules,
    _include_header,
)
from verifyci.ingestion.language import detect_language
import functools
import textwrap
from verifyci.verification.diffmap import iter_added_lines


def _bare_callee(node, source: bytes) -> set[str]:
    """Callee names for direct `name(...)` calls or qualified calls
    like `module.name(...)`."""
    names = set()
    for child in node.children:
        if child.type == "identifier":
            from verifyci.ingestion.extractor import _text
            names.add(_text(child, source))
            break
        elif child.type in ("attribute", "scoped_identifier", "qualified_identifier", "field_expression", "member_expression"):
            from verifyci.ingestion.extractor import _text
            full_attr = _text(child, source).strip()
            names.add(full_attr)
            ids = [d for d in _walk(child) if d.type in ("identifier", "type_identifier", "field_identifier", "property_identifier")]
            if ids:
                final_name = _text(ids[-1], source)
                if full_attr.startswith(("builtins.", "__builtins__.", "std::")):
                    names.add(final_name)
            break
    return names


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


@functools.lru_cache(maxsize=32)
def extract_added_refs_status(diff: str | None) -> tuple[dict[str, dict[str, set[str]]], bool, bool]:
    """Like extract_added_refs but also reports parse health:
    (refs, parse_ok, had_error). parse_ok is False when a fragment
    raised, produced no tree, or contains ERROR nodes while yielding no
    refs at all. A partial tree that still yields refs counts as usable
    (callers decide per-outcome, not per-error) — but had_error stays
    True so callers can run a lexical fallback for the specific target:
    error recovery can drop the very call being forbidden while sibling
    calls survive, which would otherwise read as a clean pass."""
    from verifyci.ingestion.parser import TreeSitterParser

    per_file: dict[str, list[str]] = {}
    for file, content in iter_added_lines(diff):
        if file is None:
            continue
        per_file.setdefault(file, []).append(content)

    refs: dict[str, dict[str, set[str]]] = {}
    had_error = False
    parser = TreeSitterParser()
    for file, lines in per_file.items():
        language = detect_language(file)
        if language not in ("python", "c", "cpp", "typescript", "tsx", "javascript"):
            continue
        try:
            parsed = parser.parse(file, textwrap.dedent(chr(10).join(lines)).encode("utf-8"), language)
        except ValueError:
            continue
        if parsed.tree is None:
            had_error = True
            continue
        root = parsed.tree.root_node
        if getattr(root, "has_error", False):
            had_error = True
        calls: set[str] = set()
        imports: set[str] = set()
        for node in _walk(root):
            if node.type in CALL_NODES:
                found_names = _bare_callee(node, parsed.source)
                calls.update(found_names)
            elif node.type in ("import_statement", "import_from_statement"):
                imports.update(_extract_import_modules(node, parsed.source))
            elif node.type == "preproc_include" and language in ("c", "cpp"):
                header = _include_header(node, parsed.source)
                if header:
                    imports.add(header)
        if calls or imports:
            refs[file] = {"calls": calls, "imports": imports}
    return refs, (bool(refs) or not had_error), had_error
