import os

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".pyi": "python",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    # Headers parse with the C++ grammar: tree-sitter-cpp covers C
    # declaration syntax, while the C grammar cannot represent classes,
    # namespaces, or templates — and real firmware headers are C++.
    # This also matches what benchmarks/score_cpp.py already assumed.
    ".h": "cpp",
    ".hpp": "cpp",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".md": "markdown",
    ".txt": "txt",
}

#: Extensions the ingester parses. Single source of truth shared by ingest
#: collection and benchmark collection. NOTE: this set does NOT decide
#: verification grounding anymore — since the C2 fail-closed repair, every
#: named-but-ungrounded file vetoes a PASS regardless of extension (a clean
#: `.py` hunk does not launder `Dockerfile`/CI/`.env` content). An extension
#: missing here means "no entities extracted" (ungrounded → INCONCLUSIVE),
#: never "exempt from the gate".
INGESTIBLE_EXTENSIONS = frozenset(LANGUAGE_BY_EXT)


def detect_language(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return LANGUAGE_BY_EXT.get(ext, "unknown")


def is_ingestible(file_path: str) -> bool:
    return os.path.splitext(file_path)[1].lower() in INGESTIBLE_EXTENSIONS
