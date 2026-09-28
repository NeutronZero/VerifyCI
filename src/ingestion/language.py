import os


def detect_language(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return {
        ".py": "python",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".md": "markdown",
        ".txt": "txt",
    }.get(ext, "unknown")
