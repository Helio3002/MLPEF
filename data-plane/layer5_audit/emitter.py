"""The audit emitter the pipeline calls on every request.

The write is **unskippable and fail-closed**: if the sink raises for any reason,
the Auditor raises AuditFailure so the orchestrator denies the call rather than
letting an unaudited action through.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from common import (
    AuditEvent,
    AuditFailure,
    Intent,
    PipelineResult,
    build_audit_event,
    now_epoch,
)


@runtime_checkable
class AuditSink(Protocol):
    """Where audit events go (control-plane store, file, memory, ...)."""

    def emit(self, event: AuditEvent) -> None: ...


class Auditor:
    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def record(
        self,
        intent: Intent,
        result: PipelineResult,
        *,
        timestamp: int | None = None,
    ) -> AuditEvent:
        event = build_audit_event(
            intent,
            result,
            timestamp=timestamp if timestamp is not None else now_epoch(),
        )
        try:
            self._sink.emit(event)
        except Exception as exc:
            # Fail closed on ANY sink error — an unaudited action must not proceed.
            raise AuditFailure(
                "audit write failed; failing closed",
                detail={"correlation_id": event.correlation_id},
            ) from exc
        return event
