ALLOWED_TOOLS = {"shell", "file_read", "file_write", "llm"}


def check_permission(tool_name: str) -> bool:
    return tool_name in ALLOWED_TOOLS
