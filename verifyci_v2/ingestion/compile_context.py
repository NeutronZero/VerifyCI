"""Canonical parse/lowering artifacts for a base/head source pair.

The pipeline owns parsing. Consumers receive these read-only-by-contract artifacts
and must not reparse or relower the source pair.
"""
from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from verifyci_v2.contracts.attestation import VerificationFinding
from verifyci_v2.contracts.canonical import content_digest_hex
from verifyci_v2.contracts.ssa_ir import FunctionUSSA


@dataclass(frozen=True, slots=True)
class AddedLineRecord:
    head_lineno: int
    hunk_index: int
    content: str


@dataclass(frozen=True, slots=True)
class IndexedAST:
    tree: ast.Module
    imports: tuple[ast.Import | ast.ImportFrom, ...]
    calls: tuple[ast.Call, ...]
    assigns: tuple[ast.Assign | ast.AnnAssign | ast.AugAssign, ...]
    compares: tuple[ast.Compare, ...]
    string_constants: tuple[ast.Constant, ...]
    functions_by_qname: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef]
    ast_structural_digest: str

    @classmethod
    def from_tree(cls, tree: ast.Module, file_path: str = "") -> "IndexedAST":
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        module_prefix = file_path.replace("\\", "/").lstrip("./")
        for suffix in (".py", ".pyi"):
            if module_prefix.endswith(suffix):
                module_prefix = module_prefix[:-len(suffix)]
                break
        module_prefix = module_prefix.replace("/", ".")

        def visit_scope(body: list[ast.stmt], scope: str = "") -> None:
            for stmt in body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local_qname = f"{scope}{stmt.name}"
                    qname = f"{module_prefix}.{local_qname}" if module_prefix else local_qname
                    functions[qname] = stmt
                    # Index nested functions for precise lookup too, but the
                    # lowerer may conservatively abstain on nested closures.
                    visit_scope(stmt.body, f"{local_qname}.")
                elif isinstance(stmt, ast.ClassDef):
                    visit_scope(stmt.body, f"{scope}{stmt.name}.")

        visit_scope(tree.body)
        nodes = tuple(ast.walk(tree))
        return cls(
            tree=tree,
            imports=tuple(n for n in nodes if isinstance(n, (ast.Import, ast.ImportFrom))),
            calls=tuple(n for n in nodes if isinstance(n, ast.Call)),
            assigns=tuple(n for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))),
            compares=tuple(n for n in nodes if isinstance(n, ast.Compare)),
            string_constants=tuple(n for n in nodes if isinstance(n, ast.Constant) and isinstance(n.value, str)),
            functions_by_qname=MappingProxyType(functions),
            ast_structural_digest=content_digest_hex(
                ast.dump(tree, include_attributes=True), domain="verifyci.v2.ast_guard"
            ),
        )

    def verify_unmutated(self) -> bool:
        """Return whether the retained AST still matches its compilation digest."""
        return self.ast_structural_digest == content_digest_hex(
            ast.dump(self.tree, include_attributes=True), domain="verifyci.v2.ast_guard"
        )


@dataclass(frozen=True, slots=True)
class CompiledFilePair:
    file_path: str
    base_source: str
    head_source: str
    added_lines: tuple[str, ...]
    added_line_records: tuple[AddedLineRecord, ...]
    diff: str
    has_stored_base: bool
    is_complete_source: bool
    is_reconstructed_from_store: bool = False
    reconstruction_failed: bool = False
    syntax_error: VerificationFinding | None = None
    base_ast: IndexedAST | None = None
    head_ast: IndexedAST | None = None
    base_ussa: Mapping[str, FunctionUSSA] = field(default_factory=lambda: MappingProxyType({}))
    head_ussa: Mapping[str, FunctionUSSA] = field(default_factory=lambda: MappingProxyType({}))


def _normalise_fragment(source: str) -> str:
    """Normalize one isolated diff fragment once, without repeated parse attempts."""
    fragment = textwrap.dedent(source)
    lines = fragment.splitlines()
    if not lines:
        return ""
    out: list[str] = []
    for i, line in enumerate(lines):
        out.append(line)
        stripped = line.strip()
        if not ((stripped.startswith("def ") or stripped.startswith("class ") or stripped.startswith("async def ")) and stripped.endswith(":")):
            continue
        following = lines[i + 1] if i + 1 < len(lines) else ""
        if not following.strip() or not following[:1].isspace():
            indent = line[:len(line) - len(line.lstrip())]
            out.append(f"{indent}    pass")
    fragment = "\n".join(out)
    if any(re.match(r"^(return|yield)\b", line) for line in fragment.splitlines()):
        fragment = "def __vc2_fragment__():\n" + textwrap.indent(fragment, "    ")
    return fragment


def _syntax_finding(file_path: str, exc: SyntaxError, *, complete: bool = True) -> VerificationFinding:
    from verifyci_v2.pipeline import finding_id
    return VerificationFinding(
        finding_id=finding_id("SYNTAX", file_path, str(exc.lineno or 1)),
        rule_id="VC2-AST-SYNTAX-ERROR",
        severity="CRITICAL",
        verdict="FAIL",
        file_path=file_path,
        start_line=exc.lineno or 1,
        end_line=exc.lineno or 1,
        message=f"Syntax error in complete source for '{file_path}': {exc}" if complete else f"Syntax error in '{file_path}': {exc}",
    )


def compile_file_pair(
    entry: Any,
    *,
    stored_source: str | None = None,
    repo_id: str = "default-repo",
) -> CompiledFilePair:
    """Reconstruct, parse, index, and lower one file pair exactly once per revision.

    `entry` is deliberately duck-typed to avoid a module cycle with pipeline.py.
    When a stored base exists, its patch is always verified before parsing.
    """
    from verifyci_v2.pipeline import apply_unified_diff_to_source
    from verifyci_v2.ingestion.ssa_lower import lower_module_to_ussa

    file_path = str(entry.file_path)
    diff = str(getattr(entry, "diff", "") or "")
    records = tuple(getattr(entry, "added_line_records", ()) or ())
    added_lines = tuple(r.content for r in records) if records else tuple(getattr(entry, "added_lines", ()) or ())
    has_stored = stored_source is not None
    complete = bool(getattr(entry, "is_complete_source", False))
    synthetic_diff = bool(getattr(entry, "diff_is_synthetic", False))
    entry_base = str(getattr(entry, "base_source", "") or "")
    entry_head = str(getattr(entry, "head_source", "") or "")
    reconstructed = False

    if has_stored:
        # Explicit complete-source API requests carry their complete buffers;
        # their generated diff may normalize EOL-only changes away. Bind the
        # supplied base to the stored snapshot, then trust the paired complete
        # head buffer only when the diff was generated from those same buffers.
        if complete and synthetic_diff:
            if entry_base != stored_source:
                return CompiledFilePair(
                    file_path=file_path, base_source=stored_source, head_source=entry_head,
                    added_lines=added_lines, added_line_records=records, diff=diff,
                    has_stored_base=True, is_complete_source=True, reconstruction_failed=True,
                )
            base, head, reconstructed = stored_source, entry_head, True
        elif diff.strip():
            head = apply_unified_diff_to_source(stored_source, diff)
            if head is None or (complete and head != entry_head):
                return CompiledFilePair(
                    file_path=file_path, base_source=stored_source, head_source=entry_head,
                    added_lines=added_lines, added_line_records=records, diff=diff,
                    has_stored_base=True, is_complete_source=complete, reconstruction_failed=True,
                )
            base, reconstructed, complete = stored_source, True, True
        else:
            # A non-synthetic empty diff cannot describe a different head tree.
            if entry_head != stored_source or entry_base != stored_source:
                return CompiledFilePair(
                    file_path=file_path, base_source=stored_source, head_source=entry_head,
                    added_lines=added_lines, added_line_records=records, diff=diff,
                    has_stored_base=True, is_complete_source=complete, reconstruction_failed=True,
                )
            base, head, complete = stored_source, stored_source, True
    else:
        base, head = entry_base, entry_head

    if not complete and not has_stored:
        base_parse_src = _normalise_fragment(base)
        head_parse_src = _normalise_fragment(head)
    else:
        base_parse_src = base
        head_parse_src = head

    # Empty source is a valid empty module; constructing it directly means no
    # parser invocation is spent on a nonexistent revision.
    trees: list[ast.Module | None] = []
    for source in (base_parse_src, head_parse_src):
        if not source:
            trees.append(ast.Module(body=[], type_ignores=[]))
            continue
        try:
            trees.append(ast.parse(source, filename=file_path))
        except (SyntaxError, ValueError, IndentationError) as exc:
            finding = _syntax_finding(file_path, exc, complete=complete or has_stored)
            return CompiledFilePair(
                file_path=file_path,
                base_source=base,
                head_source=head,
                added_lines=added_lines,
                added_line_records=records,
                diff=diff,
                has_stored_base=has_stored,
                is_complete_source=complete or has_stored,
                is_reconstructed_from_store=reconstructed,
                syntax_error=finding,
            )

    base_tree, head_tree = trees
    assert base_tree is not None and head_tree is not None
    base_index = IndexedAST.from_tree(base_tree, file_path)
    head_index = IndexedAST.from_tree(head_tree, file_path)
    try:
        base_funcs = lower_module_to_ussa(file_path, base_tree, base_parse_src, language="python", repo_id=repo_id)
        head_funcs = lower_module_to_ussa(file_path, head_tree, head_parse_src, language="python", repo_id=repo_id)
    except Exception as exc:
        from verifyci_v2.pipeline import finding_id
        finding = VerificationFinding(
            finding_id=finding_id("SSA_ERROR", file_path, type(exc).__name__),
            rule_id="VC2-SSA-LOWER-ERROR",
            severity="HIGH",
            verdict="INCONCLUSIVE",
            file_path=file_path,
            start_line=1,
            end_line=1,
            message=f"SSA lowering error for '{file_path}': {type(exc).__name__}: {exc}",
        )
        return CompiledFilePair(
            file_path=file_path, base_source=base_parse_src, head_source=head_parse_src,
            added_lines=added_lines, added_line_records=records, diff=diff,
            has_stored_base=has_stored, is_complete_source=complete or has_stored,
            is_reconstructed_from_store=reconstructed, syntax_error=finding,
            base_ast=base_index, head_ast=head_index,
        )
    return CompiledFilePair(
        file_path=file_path,
        base_source=base_parse_src,
        head_source=head_parse_src,
        added_lines=added_lines,
        added_line_records=records,
        diff=diff,
        has_stored_base=has_stored,
        is_complete_source=complete or has_stored,
        is_reconstructed_from_store=reconstructed,
        base_ast=base_index,
        head_ast=head_index,
        base_ussa=MappingProxyType({f.qualified_name: f for f in base_funcs}),
        head_ussa=MappingProxyType({f.qualified_name: f for f in head_funcs}),
    )
