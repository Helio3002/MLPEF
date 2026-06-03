"""Data-plane ingress web app: mounts the REST + OpenAI-compatible adapters.

The MCP gateway and SDK shims are embedded in their hosts (an MCP server / the
agent process), so they are not mounted here. Wire a real Proxy as `handler` at
startup (see docker-compose, Phase 11).
"""

from __future__ import annotations

from fastapi import FastAPI

from .base import GovernedHandler
from .openai_compat import create_openai_router
from .rest import create_rest_router


def create_app(handler: GovernedHandler) -> FastAPI:
    app = FastAPI(title="MLPEF Ingress", version="0.8.0")
    app.include_router(create_rest_router(handler))
    app.include_router(create_openai_router(handler))

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
