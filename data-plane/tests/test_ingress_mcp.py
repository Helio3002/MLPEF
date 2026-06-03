"""MCP gateway normalization + enforcement."""

from __future__ import annotations

from common import Intent, PipelineResult, Verdict

from ingress import McpGateway
from proxy import PipelineOutcome


def _outcome(verdict: Verdict, *, output: str = "", reason: str = "") -> PipelineOutcome:
    result = PipelineResult(intent_id="cid", final_verdict=verdict, reason=reason)
    return PipelineOutcome(result=result, output=output)


class FakeHandler:
    def __init__(self, outcome: PipelineOutcome) -> None:
        self.outcome = outcome
        self.seen: Intent | None = None

    def handle(self, intent: Intent, *, credential: str) -> PipelineOutcome:
        self.seen = intent
        return self.outcome


def test_mcp_allow_returns_text_content() -> None:
    handler = FakeHandler(_outcome(Verdict.ALLOW, output="ok"))
    gateway = McpGateway(handler, agent_id="a", credential="k")
    result = gateway.call_tool("fs.read", {"path": "notes.txt"})
    assert result["isError"] is False
    assert result["content"][0]["text"] == "ok"


def test_mcp_deny_is_error() -> None:
    handler = FakeHandler(_outcome(Verdict.DENY, reason="denied"))
    gateway = McpGateway(handler, agent_id="a", credential="k")
    result = gateway.call_tool("fs.delete", {"path": "x"})
    assert result["isError"] is True
    assert "[mlpef:deny]" in result["content"][0]["text"]


def test_mcp_normalizes_identity_resource_and_token() -> None:
    handler = FakeHandler(_outcome(Verdict.ALLOW))
    gateway = McpGateway(handler, agent_id="agent-7", credential="k", tenant="acme")
    gateway.call_tool("fs.read", {"resource": "/work/a", "approval_token": "tok"})
    assert handler.seen is not None
    assert handler.seen.agent_id == "agent-7"
    assert handler.seen.tenant == "acme"
    assert handler.seen.resource == "/work/a"
    assert handler.seen.approval_token == "tok"
