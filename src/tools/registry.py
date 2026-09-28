from typing import Any, Callable


class ToolRegistry:
    def __init__(self):
        self._tools = {}

    def register(self, name: str, func: Callable, description: str = ""):
        self._tools[name] = {"func": func, "description": description}

    def get(self, name: str) -> Callable | None:
        tool = self._tools.get(name)
        return tool["func"] if tool else None

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())
