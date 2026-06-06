"""Runnable proxy entrypoint — serves the HTTP ingress app.

`docker compose` runs this as `uvicorn proxy.server:app`. It builds the Proxy from
the environment (see `proxy.builder`) and wraps it in the REST + OpenAI-compatible
ingress FastAPI app. The MCP gateway server (`ingress.mcp_server`) reuses the same
`build_proxy()` to wire identical enforcement over the MCP transport.

Audit goes to stdout by default; set `MLPEF_AUDIT_URL` + `MLPEF_AUDIT_AGENT_KEY` to
POST events to the control-plane store. The sandbox is opt-in
(`MLPEF_SANDBOX_ENABLED`); see `proxy.builder` and THREAT_MODEL.md R-30.
"""

from __future__ import annotations

from fastapi import FastAPI

from ingress.app import create_app

from .builder import build_proxy


def build_app() -> FastAPI:
    return create_app(build_proxy())


app = build_app()
