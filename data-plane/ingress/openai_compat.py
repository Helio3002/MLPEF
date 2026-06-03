"""OpenAI-compatible tool/function-call shim.

Accepts OpenAI-style `tool_calls` (function name + JSON-string arguments), enforces
each through the pipeline, and returns OpenAI-style `tool` messages — denied calls
come back as a `[mlpef:...]` message the model can read instead of the tool result.
"""

from __future__ import annotations

import json
from typing import Annotated

from common import IngressSource
from fastapi import APIRouter, Header
from pydantic import BaseModel

from .base import GovernedHandler, build_intent


class _Function(BaseModel):
    name: str
    arguments: str = "{}"  # OpenAI sends arguments as a JSON string


class OpenAIToolCall(BaseModel):
    id: str
    function: _Function


class OpenAIToolCallRequest(BaseModel):
    tool_calls: list[OpenAIToolCall]
    tenant: str = "default"


class OpenAIToolMessage(BaseModel):
    tool_call_id: str
    role: str = "tool"
    content: str


class OpenAIToolCallResponse(BaseModel):
    tool_messages: list[OpenAIToolMessage]


def _parse_arguments(raw: str) -> dict[str, object]:
    try:
        parsed = json.loads(raw)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def create_openai_router(handler: GovernedHandler) -> APIRouter:
    router = APIRouter(prefix="/openai/v1", tags=["ingress-openai"])

    @router.post("/tool-calls", response_model=OpenAIToolCallResponse)
    def tool_calls(
        body: OpenAIToolCallRequest,
        x_agent_id: Annotated[str, Header()],
        x_agent_key: Annotated[str, Header()],
    ) -> OpenAIToolCallResponse:
        messages: list[OpenAIToolMessage] = []
        for call in body.tool_calls:
            arguments = _parse_arguments(call.function.arguments)
            intent = build_intent(
                agent_id=x_agent_id,
                tenant=body.tenant,
                tool=call.function.name,
                action=call.function.name,
                resource=str(arguments.get("resource", "-")),
                arguments=arguments,
                ingress=IngressSource.OPENAI_COMPAT,
            )
            outcome = handler.handle(intent, credential=x_agent_key)
            if outcome.result.allowed:
                content = outcome.output
            else:
                content = f"[mlpef:{outcome.result.final_verdict.value}] {outcome.result.reason}"
            messages.append(OpenAIToolMessage(tool_call_id=call.id, content=content))
        return OpenAIToolCallResponse(tool_messages=messages)

    return router
