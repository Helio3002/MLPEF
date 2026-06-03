"""OpenAI-compatible tool-call shim."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from common import Intent, PipelineResult, Verdict
from ingress.openai_compat import create_openai_router
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


def _client(outcome: PipelineOutcome) -> TestClient:
    app = FastAPI()
    app.include_router(create_openai_router(FakeHandler(outcome)))
    return TestClient(app)


_HEADERS = {"X-Agent-Id": "agent-1", "X-Agent-Key": "key"}


def test_openai_allow_returns_tool_message() -> None:
    client = _client(_outcome(Verdict.ALLOW, output="sunny, 21C"))
    call = {"id": "c1", "function": {"name": "get_weather", "arguments": '{"city": "SF"}'}}
    resp = client.post("/openai/v1/tool-calls", json={"tool_calls": [call]}, headers=_HEADERS)
    assert resp.status_code == 200
    message = resp.json()["tool_messages"][0]
    assert message["tool_call_id"] == "c1"
    assert message["content"] == "sunny, 21C"


def test_openai_deny_returns_denial_content() -> None:
    client = _client(_outcome(Verdict.DENY, reason="blocked"))
    call = {"id": "c2", "function": {"name": "rm_rf", "arguments": "{}"}}
    resp = client.post("/openai/v1/tool-calls", json={"tool_calls": [call]}, headers=_HEADERS)
    assert "[mlpef:deny]" in resp.json()["tool_messages"][0]["content"]
