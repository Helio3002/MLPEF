"""Audit sinks.

`InMemoryAuditSink` is for tests/dev. `HttpAuditSink` POSTs each event to the
control-plane `/audit` endpoint (used by the proxy in Phase 8); any non-2xx or
transport error raises, so the Auditor fails closed.
"""

from __future__ import annotations

from common import AuditEvent


class InMemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class HttpAuditSink:
    def __init__(self, base_url: str, agent_key: str, *, timeout: float = 2.0) -> None:
        self._url = base_url.rstrip("/") + "/audit"
        self._headers = {"X-Agent-Key": agent_key}
        self._timeout = timeout

    def emit(self, event: AuditEvent) -> None:
        import httpx  # lazy import: package stays importable without httpx for tests

        response = httpx.post(
            self._url,
            json=event.model_dump(mode="json"),
            headers=self._headers,
            timeout=self._timeout,
        )
        response.raise_for_status()
