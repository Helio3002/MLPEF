"""Tests for Intent strictness and Decision/PipelineResult derivation."""

from __future__ import annotations

import pytest
from common import (
    DenyReasonCode,
    IngressSource,
    Intent,
    LayerDecision,
    LayerName,
    PathTraversalAttempt,
    PipelineResult,
    Verdict,
)
from pydantic import ValidationError


def _intent() -> Intent:
    return Intent(
        intent_id="i-1",
        agent_id="agent-1",
        tenant="tenant-a",
        tool="filesystem",
        action="fs.read",
        resource="/data/x.txt",
        ingress=IngressSource.MCP,
        received_at=1_700_000_000,
    )


def test_intent_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Intent(
            intent_id="i-1",
            agent_id="agent-1",
            tenant="tenant-a",
            tool="filesystem",
            action="fs.read",
            resource="/data/x.txt",
            ingress=IngressSource.MCP,
            received_at=1_700_000_000,
            sneaky_extra="payload",  # type: ignore[call-arg]
        )


def test_intent_is_frozen() -> None:
    intent = _intent()
    with pytest.raises((ValidationError, TypeError)):
        intent.action = "fs.delete"


def test_layer_decision_helpers() -> None:
    allow = LayerDecision.allow(LayerName.L1_VALIDATION)
    assert allow.verdict is Verdict.ALLOW
    assert allow.reason_code is None

    deny = LayerDecision.deny(
        LayerName.L2_POLICY,
        DenyReasonCode.POLICY_DEFAULT_DENY,
        "no rule matched",
    )
    assert deny.verdict is Verdict.DENY
    assert deny.reason_code is DenyReasonCode.POLICY_DEFAULT_DENY

    hitl = LayerDecision.hitl_required(LayerName.L2_POLICY, "needs approval")
    assert hitl.verdict is Verdict.HITL_REQUIRED
    assert hitl.reason_code is DenyReasonCode.HITL_REQUIRED


def test_layer_decision_from_error_preserves_code_and_security_flag() -> None:
    err = PathTraversalAttempt("escaped jail", detail={"path": "/etc/passwd"})
    decision = LayerDecision.from_error(err)
    assert decision.layer is LayerName.L1_VALIDATION
    assert decision.reason_code is DenyReasonCode.PATH_TRAVERSAL
    assert decision.verdict is Verdict.DENY
    assert decision.security_event is True
    assert decision.metadata == {"path": "/etc/passwd"}


def test_pipeline_result_all_allow() -> None:
    layers = [
        LayerDecision.allow(LayerName.L1_VALIDATION),
        LayerDecision.allow(LayerName.L2_POLICY),
    ]
    result = PipelineResult.from_layers("i-1", layers)
    assert result.allowed is True
    assert result.final_verdict is Verdict.ALLOW


def test_pipeline_result_first_non_allow_decides() -> None:
    layers = [
        LayerDecision.allow(LayerName.L1_VALIDATION),
        LayerDecision.deny(
            LayerName.L2_POLICY,
            DenyReasonCode.POLICY_DENY,
            "denied by policy",
            security_event=False,
        ),
    ]
    result = PipelineResult.from_layers("i-1", layers)
    assert result.allowed is False
    assert result.final_verdict is Verdict.DENY
    assert result.reason_code is DenyReasonCode.POLICY_DENY


def test_pipeline_result_propagates_security_event() -> None:
    layers = [
        LayerDecision.deny(
            LayerName.L1_VALIDATION,
            DenyReasonCode.PATH_TRAVERSAL,
            "traversal",
            security_event=True,
        ),
    ]
    result = PipelineResult.from_layers("i-1", layers)
    assert result.security_event is True
