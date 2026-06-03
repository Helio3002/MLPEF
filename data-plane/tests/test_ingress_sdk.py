"""SDK shims: governed decorator + LangChain-style GovernedTool."""

from __future__ import annotations

import pytest
from common import Intent, PipelineResult, Verdict

from ingress import GovernanceDenied, GovernedTool, governed
from proxy import PipelineOutcome


def _outcome(verdict: Verdict, *, reason: str = "") -> PipelineOutcome:
    result = PipelineResult(intent_id="cid", final_verdict=verdict, reason=reason)
    return PipelineOutcome(result=result, output="")


class FakeHandler:
    def __init__(self, outcome: PipelineOutcome) -> None:
        self.outcome = outcome
        self.seen: Intent | None = None

    def handle(self, intent: Intent, *, credential: str) -> PipelineOutcome:
        self.seen = intent
        return self.outcome


def test_governed_decorator_allows_and_runs_fn() -> None:
    handler = FakeHandler(_outcome(Verdict.ALLOW))

    @governed(handler, agent_id="a", credential="k", tool="adder")
    def add(x: int, y: int) -> int:
        return x + y

    assert add(x=2, y=3) == 5
    assert handler.seen is not None
    assert handler.seen.tool == "adder"
    assert handler.seen.arguments == {"x": 2, "y": 3}


def test_governed_decorator_denies() -> None:
    handler = FakeHandler(_outcome(Verdict.DENY, reason="nope"))

    @governed(handler, agent_id="a", credential="k", tool="adder")
    def add(x: int, y: int) -> int:
        return x + y

    with pytest.raises(GovernanceDenied):
        add(x=1, y=1)


def test_governed_tool_allows_and_denies() -> None:
    allow_tool = GovernedTool(
        name="adder",
        description="adds two numbers",
        func=lambda x, y: x + y,
        handler=FakeHandler(_outcome(Verdict.ALLOW)),
        agent_id="a",
        credential="k",
    )
    assert allow_tool.run(x=4, y=5) == 9

    deny_tool = GovernedTool(
        name="adder",
        description="adds two numbers",
        func=lambda x, y: x + y,
        handler=FakeHandler(_outcome(Verdict.DENY, reason="no")),
        agent_id="a",
        credential="k",
    )
    with pytest.raises(GovernanceDenied):
        deny_tool.run(x=1, y=1)
