"""Tests for the fail-closed Layer 5 audit emitter."""

from __future__ import annotations

import pytest
from common import (
    AuditEvent,
    AuditFailure,
    IngressSource,
    Intent,
    LayerDecision,
    LayerName,
    PipelineResult,
    Verdict,
)

from layer5_audit import Auditor, InMemoryAuditSink


def _intent() -> Intent:
    return Intent(
        intent_id="i-1",
        agent_id="agent-1",
        tenant="default",
        tool="filesystem",
        action="fs.read",
        resource="/x",
        ingress=IngressSource.MCP,
        received_at=1,
    )


def _result() -> PipelineResult:
    return PipelineResult.from_layers("i-1", [LayerDecision.allow(LayerName.L1_VALIDATION)])


def test_records_event_to_sink() -> None:
    sink = InMemoryAuditSink()
    event = Auditor(sink).record(_intent(), _result(), timestamp=123)
    assert len(sink.events) == 1
    assert sink.events[0].correlation_id == "i-1"
    assert event.final_verdict is Verdict.ALLOW


class _FailingSink:
    def emit(self, event: AuditEvent) -> None:
        raise RuntimeError("audit store unreachable")


def test_emit_failure_fails_closed() -> None:
    auditor = Auditor(_FailingSink())
    with pytest.raises(AuditFailure):
        auditor.record(_intent(), _result(), timestamp=123)
