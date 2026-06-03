"""REST ingress adapter: normalization + verdict->status mapping."""

from __future__ import annotations

from common import DenyReasonCode, Intent, PipelineResult, Verdict
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ingress.rest import create_rest_router
from proxy import PipelineOutcome


def _outcome(
    verdict: Verdict,
    *,
    output: str = "",
    reason_code: DenyReasonCode | None = None,
    reason: str = "",
) -> PipelineOutcome:
    result = PipelineResult(
        intent_id="cid", final_verdict=verdict, reason_code=reason_code, reason=reason
    )
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
    app.include_router(create_rest_router(FakeHandler(outcome)))
    return TestClient(app)


_HEADERS = {"X-Agent-Id": "agent-1", "X-Agent-Key": "key"}
_BODY = {"tool": "shell.exec", "action": "shell.exec", "resource": "-"}


def test_rest_allow_returns_200_and_output() -> None:
    client = _client(_outcome(Verdict.ALLOW, output="result"))
    resp = client.post("/v1/execute", json=_BODY, headers=_HEADERS)
    assert resp.status_code == 200
    assert resp.json()["verdict"] == "allow"
    assert resp.json()["output"] == "result"


def test_rest_deny_maps_to_403() -> None:
    outcome = _outcome(Verdict.DENY, reason_code=DenyReasonCode.POLICY_DEFAULT_DENY, reason="no")
    resp = _client(outcome).post("/v1/execute", json=_BODY, headers=_HEADERS)
    assert resp.status_code == 403
    assert resp.json()["reason_code"] == "policy_default_deny"


def test_rest_hitl_maps_to_202() -> None:
    client = _client(_outcome(Verdict.HITL_REQUIRED))
    resp = client.post("/v1/execute", json=_BODY, headers=_HEADERS)
    assert resp.status_code == 202


def test_rest_missing_agent_headers_is_422() -> None:
    resp = _client(_outcome(Verdict.ALLOW)).post("/v1/execute", json=_BODY)
    assert resp.status_code == 422
