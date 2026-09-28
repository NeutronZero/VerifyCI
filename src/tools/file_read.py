from pathlib import Path


def file_read_tool(file_path: str) -> dict:
    try:
        content = Path(file_path).read_text(encoding="utf-8")
        return {"content": content, "error": None}
    except Exception as e:
        return {"content": None, "error": str(e)}
