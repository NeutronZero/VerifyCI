from src.tools.sandbox import run_sandboxed


def shell_tool(command: list[str]) -> dict:
    return run_sandboxed(command)
