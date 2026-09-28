import os

LANGUAGE_BY_EXT = {
    ".py": "python",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".md": "markdown",
    ".txt": "txt",
}

#: Extensions the ingester parses. Single source of truth shared by ingest
#: collection and verification grounding (a changed file outside this set
#: is legitimately ungroundable and must not veto a diff).
INGESTIBLE_EXTENSIONS = frozenset(LANGUAGE_BY_EXT)


def detect_language(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return LANGUAGE_BY_EXT.get(ext, "unknown")


def is_ingestible(file_path: str) -> bool:
    return os.path.splitext(file_path)[1].lower() in INGESTIBLE_EXTENSIONS
