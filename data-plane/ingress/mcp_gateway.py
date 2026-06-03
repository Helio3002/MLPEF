"""MCP gateway — the primary universal path.

MLPEF sits between an MCP-capable agent and downstream MCP tool servers. Mount
`McpGateway.call_tool` inside your MCP server's `tools/call` handler and any
MCP-capable agent is governed with zero code changes. This module is the governed
normalization + enforcement core; the MCP transport (stdio / SSE / WebSocket) is
provided by your MCP server. The return shape matches MCP's CallToolResult
(`content` + `isError`).
"""

from __future__ import annotations

from typing import Any

from common import IngressSource

from .base import GovernedHandler, build_intent


class McpGateway:
    def __init__(
        self,
        handler: GovernedHandler,
        *,
        agent_id: str,
        credential: str,
        tenant: str = "default",
    ) -> None:
        self._handler = handler
        self._agent_id = agent_id
        self._credential = credential
        self._tenant = tenant

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        token = arguments.get("approval_token")
        intent = build_intent(
            agent_id=self._agent_id,
            tenant=self._tenant,
            tool=name,
            action=name,
            resource=str(arguments.get("resource", "-")),
            arguments=arguments,
            ingress=IngressSource.MCP,
            approval_token=token if isinstance(token, str) else None,
        )
        outcome = self._handler.handle(intent, credential=self._credential)
        if outcome.result.allowed:
            return {"isError": False, "content": [{"type": "text", "text": outcome.output}]}
        text = f"[mlpef:{outcome.result.final_verdict.value}] {outcome.result.reason}"
        return {"isError": True, "content": [{"type": "text", "text": text}]}
