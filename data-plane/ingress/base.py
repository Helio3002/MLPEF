"""Shared ingress primitives.

Every adapter normalizes its native input into the same `Intent` and submits it to
a `GovernedHandler` (the Proxy). This module holds the normalization helper and the
response shape; it carries no web-framework imports so it can be reused by the
framework-free adapters (MCP gateway, SDK shims).
"""

from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable

from common import IngressSource, Intent, now_epoch
from pydantic import BaseModel, ConfigDict, JsonValue

from proxy import PipelineOutcome


@runtime_checkable
class GovernedHandler(Protocol):
    """Anything that runs an Intent through the five-layer pipeline (the Proxy)."""

    def handle(self, intent: Intent, *, credential: str) -> PipelineOutcome: ...


def build_intent(
    *,
    agent_id: str,
    tenant: str,
    tool: str,
    action: str,
    resource: str,
    arguments: dict[str, JsonValue],
    ingress: IngressSource,
    approval_token: str | None = None,
) -> Intent:
    """Normalize adapter input into the canonical Intent (assigns the correlation
    id + receive time). agent_id/credential are bound server-side at resolution."""
    return Intent(
        intent_id=uuid.uuid4().hex,
        agent_id=agent_id,
        tenant=tenant,
        tool=tool,
        action=action,
        resource=resource,
        arguments=arguments,
        ingress=ingress,
        received_at=now_epoch(),
        approval_token=approval_token,
    )


class ExecuteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str
    reason_code: str | None
    reason: str
    output: str
    correlation_id: str
    security_event: bool


def outcome_to_response(outcome: PipelineOutcome) -> ExecuteResponse:
    result = outcome.result
    return ExecuteResponse(
        verdict=result.final_verdict.value,
        reason_code=result.reason_code.value if result.reason_code is not None else None,
        reason=result.reason,
        output=outcome.output,
        correlation_id=result.intent_id,
        security_event=result.security_event,
    )
