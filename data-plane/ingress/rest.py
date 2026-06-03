"""Plain REST ingress: POST /v1/execute. The lowest-common-denominator adapter."""

from __future__ import annotations

from typing import Annotated

from common import IngressSource, Verdict
from fastapi import APIRouter, Header, Response, status
from pydantic import BaseModel, Field, JsonValue

from .base import ExecuteResponse, GovernedHandler, build_intent, outcome_to_response


class ExecuteRequest(BaseModel):
    tool: str
    action: str
    resource: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    tenant: str = "default"
    approval_token: str | None = None


_VERDICT_STATUS = {
    Verdict.ALLOW: status.HTTP_200_OK,
    Verdict.HITL_REQUIRED: status.HTTP_202_ACCEPTED,
    Verdict.DENY: status.HTTP_403_FORBIDDEN,
}


def create_rest_router(handler: GovernedHandler) -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["ingress-rest"])

    @router.post("/execute", response_model=ExecuteResponse)
    def execute(
        body: ExecuteRequest,
        response: Response,
        x_agent_id: Annotated[str, Header()],
        x_agent_key: Annotated[str, Header()],
    ) -> ExecuteResponse:
        intent = build_intent(
            agent_id=x_agent_id,
            tenant=body.tenant,
            tool=body.tool,
            action=body.action,
            resource=body.resource,
            arguments=dict(body.arguments),
            ingress=IngressSource.REST,
            approval_token=body.approval_token,
        )
        outcome = handler.handle(intent, credential=x_agent_key)
        response.status_code = _VERDICT_STATUS.get(
            outcome.result.final_verdict, status.HTTP_200_OK
        )
        return outcome_to_response(outcome)

    return router
