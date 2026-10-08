"""OTel GenAI semconv compat layer.

Falls back to placeholder attributes when the semantic-conventions package
is absent so core flows work offline; real attributes apply when installed.
"""
__all__ = [
    "GenAiAgentId",
    "GenAiAgentName",
    "GenAiAgentVersion",
    "GenAiAgentDescription",
    "GenAiConversationId",
    "GenAiOperationName",
    "GenAiUsageInputTokens",
    "GenAiUsageOutputTokens",
]
try:
    import importlib as _importlib

    _gen_ai = _importlib.import_module("opentelemetry.semconv.gen_ai")
    GenAiAgentId = _gen_ai.GenAiAgentId
    GenAiAgentName = _gen_ai.GenAiAgentName
    GenAiAgentVersion = _gen_ai.GenAiAgentVersion
    GenAiAgentDescription = _gen_ai.GenAiAgentDescription
    GenAiConversationId = _gen_ai.GenAiConversationId
    GenAiOperationName = _gen_ai.GenAiOperationName
    GenAiUsageInputTokens = _gen_ai.GenAiUsageInputTokens
    GenAiUsageOutputTokens = _gen_ai.GenAiUsageOutputTokens
except (ImportError, AttributeError):
    from typing import Any as _Any

    class _Attr:
        KEY: str = ""

        def __init__(self, key: str = "") -> None:
            self.KEY = key

    def _attr(key: str) -> _Any:
        return _Attr(key)

    GenAiAgentId = _attr("gen_ai.agent.id")
    GenAiAgentName = _attr("gen_ai.agent.name")
    GenAiAgentVersion = _attr("gen_ai.agent.version")
    GenAiAgentDescription = _attr("gen_ai.agent.description")
    GenAiConversationId = _attr("gen_ai.conversation.id")
    GenAiOperationName = _attr("gen_ai.operation.name")
    GenAiUsageInputTokens = _attr("gen_ai.usage.input_tokens")
    GenAiUsageOutputTokens = _attr("gen_ai.usage.output_tokens")
