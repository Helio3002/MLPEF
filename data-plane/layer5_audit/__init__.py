"""Layer 5 — tamper-evident audit emitter (data plane).

The Auditor builds an AuditEvent from an intent + pipeline result and pushes it to
a sink. The chain itself is sealed server-side by the control-plane audit store
(see common.audit / control-api), so emitters stay stateless and the chain stays
consistent across a horizontally-scaled proxy fleet.
"""

from __future__ import annotations

from .emitter import Auditor, AuditSink
from .sinks import HttpAuditSink, InMemoryAuditSink

__all__ = ["AuditSink", "Auditor", "HttpAuditSink", "InMemoryAuditSink"]
