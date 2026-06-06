"""FastAPI application factory for the control-api."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import agents, audit, auth, hitl, profiles, tools


def create_app() -> FastAPI:
    app = FastAPI(title="MLPEF Control API", version="0.2.0")
    new_var = ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=new_var,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )
    app.include_router(auth.router)
    app.include_router(agents.router)
    app.include_router(profiles.router)
    app.include_router(tools.router)
    app.include_router(audit.router)
    app.include_router(hitl.router)

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
