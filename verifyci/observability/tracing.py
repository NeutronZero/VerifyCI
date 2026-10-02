from opentelemetry import trace

from verifyci.observability.genai_semconv import (
    GenAiAgentName,
    GenAiAgentDescription,
    GenAiAgentVersion,
    GenAiConversationId,
    GenAiOperationName,
)

tracer = trace.get_tracer("verifyci")


def start_agent_span(name: str, conversation_id: str, operation: str):
    return tracer.start_as_current_span(
        name,
        attributes={
            GenAiConversationId.KEY: conversation_id,
            GenAiAgentName.KEY: "VerifyCI",
            GenAiAgentDescription.KEY: "Verification-first code intelligence",
            GenAiAgentVersion.KEY: "0.1.0",  # must match pyproject.toml version
            GenAiOperationName.KEY: operation,
        },
    )
