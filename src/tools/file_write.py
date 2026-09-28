from pathlib import Path


def file_write_tool(file_path: str, content: str) -> dict:
    try:
        Path(file_path).write_text(content, encoding="utf-8")
        return {"success": True, "error": None}
    except Exception as e:
        return {"success": False, "error": str(e)}
