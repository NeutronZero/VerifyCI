"""OTel GenAI semconv compat layer.

Falls back to placeholder attributes when the semantic-conventions package
is absent so core flows work offline; real attributes apply when installed.
"""
try:
    from opentelemetry.semconv.gen_ai import (
        GenAiAgentId,
        GenAiAgentName,
        GenAiAgentVersion,
        GenAiAgentDescription,
        GenAiConversationId,
        GenAiOperationName,
        GenAiUsageInputTokens,
        GenAiUsageOutputTokens,
    )
except ImportError:
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
