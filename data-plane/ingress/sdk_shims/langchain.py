"""A LangChain-style governed tool wrapper (reference SDK shim).

`GovernedTool` exposes `name` / `description` / `run(**kwargs)` matching the
LangChain BaseTool shape closely enough to drop into a LangChain agent, while
enforcing every invocation through the pipeline first. No hard `langchain`
dependency — it's a structural reference.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from common import IngressSource

from ..base import GovernedHandler, build_intent
from .decorator import GovernanceDenied


class GovernedTool:
    def __init__(
        self,
        *,
        name: str,
        description: str,
        func: Callable[..., Any],
        handler: GovernedHandler,
        agent_id: str,
        credential: str,
        tenant: str = "default",
        resource_key: str | None = None,
    ) -> None:
        self.name = name
        self.description = description
        self._func = func
        self._handler = handler
        self._agent_id = agent_id
        self._credential = credential
        self._tenant = tenant
        self._resource_key = resource_key

    def run(self, **kwargs: Any) -> Any:
        token = kwargs.get("approval_token")
        arguments = {key: value for key, value in kwargs.items() if key != "approval_token"}
        resource = str(kwargs.get(self._resource_key, "-")) if self._resource_key else "-"
        intent = build_intent(
            agent_id=self._agent_id,
            tenant=self._tenant,
            tool=self.name,
            action=self.name,
            resource=resource,
            arguments=arguments,
            ingress=IngressSource.SDK_SHIM,
            approval_token=token if isinstance(token, str) else None,
        )
        outcome = self._handler.handle(intent, credential=self._credential)
        if not outcome.result.allowed:
            verdict = outcome.result.final_verdict.value
            raise GovernanceDenied(f"MLPEF {verdict} for {self.name}: {outcome.result.reason}")
        return self._func(**arguments)
