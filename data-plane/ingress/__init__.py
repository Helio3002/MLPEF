"""MLPEF ingress adapters.

Every adapter normalizes its native input into the same `Intent` and submits it to
the identical five-layer pipeline. Coverage depends on agents routing through one
of these adapters — **traffic that bypasses the gateway is unguarded** (see the
README and THREAT_MODEL.md R-1).

Framework-agnostic pieces are exported here; the FastAPI routers live in
`ingress.rest` / `ingress.openai_compat` / `ingress.app` so importing `ingress`
does not require FastAPI.
"""

from __future__ import annotations

from .base import ExecuteResponse, GovernedHandler, build_intent, outcome_to_response
from .mcp_gateway import McpGateway
from .sdk_shims import GovernanceDenied, GovernedTool, governed

__all__ = [
    "ExecuteResponse",
    "GovernanceDenied",
    "GovernedHandler",
    "GovernedTool",
    "McpGateway",
    "build_intent",
    "governed",
    "outcome_to_response",
]
