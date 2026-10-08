import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Tree


@dataclass
class ParsedFile:
    file_path: str
    source: bytes
    source_hash: str
    language: str
    tree: "Tree | None" = None


def compute_source_hash(source: bytes) -> str:
    # LF-normalised identity hashing: a CRLF checkout (autocrlf) of
    # identical content must yield the identical revision. Stored
    # snippets keep raw bytes; only the hash normalises.
    return hashlib.sha256(
        source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()


class TreeSitterParser:
    def __init__(self):
        self._parsers = {}

    def _get_parser(self, language: str):
        if language not in self._parsers:
            import tree_sitter_python as tspython
            import tree_sitter_cpp as tscpp
            import tree_sitter_c as tsc
            import tree_sitter_typescript as tstypescript
            import tree_sitter_javascript as tsjavascript
            from tree_sitter import Parser, Language

            lang_map = {
                "python": Language(tspython.language()),
                "cpp": Language(tscpp.language()),
                "c": Language(tsc.language()),
                "typescript": Language(tstypescript.language_typescript()),
                "tsx": Language(tstypescript.language_tsx()),
                "javascript": Language(tsjavascript.language()),
            }
            if language in lang_map:
                parser = Parser(lang_map[language])
                self._parsers[language] = parser
            else:
                raise ValueError(f"unsupported language: {language}")
        return self._parsers[language]

    def raw_parser(self, language: str):
        """Expose the underlying tree-sitter Parser.

        Exists so incremental re-parse can pass ``old_tree`` through the
        supported abstraction instead of reaching into internals.
        """
        return self._get_parser(language)

    def parse(self, file_path: str, source: bytes, language: str) -> ParsedFile:
        source_hash = compute_source_hash(source)
        parser = self._get_parser(language)
        tree = None
        if parser:
            tree = parser.parse(source)
        return ParsedFile(
            file_path=file_path,
            source=source,
            source_hash=source_hash,
            language=language,
            tree=tree,
        )
