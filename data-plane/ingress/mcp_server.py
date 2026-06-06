"""Runnable MLPEF MCP gateway server — the no-code MCP integration path.

Point any MCP-capable agent (Claude Desktop, Cline, Cursor, LangGraph via
`langchain-mcp-adapters`, …) at this server and every tool call it makes is
enforced through the full five-layer pipeline — **no agent code changes**. You
only configure it (which agent identity + which tools) via environment variables.

How it fits together:

    MCP agent ──(MCP: stdio | SSE)──► this server ──► McpGateway ──► Proxy (L1..L5)
                                                                       │
                                              control-api (config/audit/nonce/keys)

The MLPEF enforcement core is the already-tested `McpGateway`; this module is only
the thin MCP-protocol shell around it. It builds a full in-process `Proxy` via
`proxy.builder.build_proxy` (so config-signature verification, the single-use nonce
store, audit, and the sandbox policy all apply exactly as in the HTTP proxy).

Configuration (environment):
  MLPEF_MCP_AGENT_ID     (required)  the registered agent this gateway acts as
  MLPEF_MCP_AGENT_KEY    (required)  that agent's API key
  MLPEF_MCP_TENANT       (default "default")
  MLPEF_MCP_TOOLS        comma-separated tool names to advertise
                         (default "fs.read,fs.write,shell.exec,http.get")
  MLPEF_MCP_TRANSPORT    "sse" (default; connect by URL) or "stdio" (client spawns it)
  MLPEF_MCP_HOST/PORT    SSE bind (default 0.0.0.0:9000)
  + all the proxy env vars consumed by proxy.builder (control-plane URL, etc.)

One gateway instance represents **one** registered agent identity (MCP's basic
transports carry no per-call credential). Run one per agent, or front several
behind your own auth. Coverage still depends on the agent being unable to reach
its tools except through here (THREAT_MODEL.md R-1).

Targets the `mcp` Python SDK (`pip install -e ".[proxy]"` pulls it in). The MCP
protocol shell is the only version-sensitive part; the MLPEF routing is not.
"""

from __future__ import annotations

import os
import sys
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from proxy.builder import build_proxy

from .mcp_gateway import McpGateway

_SERVER_NAME = "mlpef-gateway"
_SERVER_VERSION = "0.1.0"
_DEFAULT_TOOLS = "fs.read,fs.write,shell.exec,http.get"


def _tool_defs(tool_names: list[str]) -> list[types.Tool]:
    """Advertise the configured tools. The input schema is intentionally permissive
    — MLPEF Layer 1 performs the real, per-tool argument validation, so this is only
    a hint to the agent."""
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "resource": {"type": "string", "description": "target resource (path/URL)"},
            "approval_token": {
                "type": "string",
                "description": "MLPEF HITL approval token, for retrying a gated call",
            },
        },
        "additionalProperties": True,
    }
    return [
        types.Tool(
            name=name,
            description=f"{name} — governed by MLPEF (validated, policy-checked, audited)",
            inputSchema=schema,
        )
        for name in tool_names
    ]


def _build_server(gateway: McpGateway, tool_names: list[str]) -> Server:
    server: Server = Server(_SERVER_NAME)
    tools = _tool_defs(tool_names)

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return tools

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
        # McpGateway runs the call through L1..L5 and returns MCP CallToolResult
        # content. Denials come back as readable "[mlpef:deny] …" text (same as the
        # OpenAI shim) so the model can see why it was blocked and adapt.
        result = gateway.call_tool(name, arguments or {})
        return [
            types.TextContent(type="text", text=str(block.get("text", "")))
            for block in result["content"]
        ]

    return server


def _init_options(server: Server) -> InitializationOptions:
    return InitializationOptions(
        server_name=_SERVER_NAME,
        server_version=_SERVER_VERSION,
        capabilities=server.get_capabilities(
            notification_options=NotificationOptions(),
            experimental_capabilities={},
        ),
    )


def _run_stdio(server: Server, init_options: InitializationOptions) -> None:
    import anyio
    from mcp.server.stdio import stdio_server

    async def _main() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, init_options)

    anyio.run(_main)


def _run_sse(server: Server, init_options: InitializationOptions, host: str, port: int) -> None:
    import uvicorn
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.routing import Mount, Route

    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(request.scope, request.receive, request._send) as streams:
            await server.run(streams[0], streams[1], init_options)

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ]
    )
    uvicorn.run(app, host=host, port=port)


def _run_streamable_http(server: Server, host: str, port: int) -> None:
    # The modern MCP HTTP transport (single /mcp endpoint). Newer clients prefer
    # this over SSE; the SDK owns the wire details so it stays version-correct.
    import contextlib
    from collections.abc import AsyncIterator

    import uvicorn
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Mount

    manager = StreamableHTTPSessionManager(app=server, stateless=True)

    async def handle_mcp(scope: Any, receive: Any, send: Any) -> None:
        await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    app = Starlette(routes=[Mount("/mcp", app=handle_mcp)], lifespan=lifespan)
    uvicorn.run(app, host=host, port=port)


def main() -> int:
    agent_id = os.environ.get("MLPEF_MCP_AGENT_ID")
    agent_key = os.environ.get("MLPEF_MCP_AGENT_KEY")
    if not agent_id or not agent_key:
        print("MLPEF_MCP_AGENT_ID and MLPEF_MCP_AGENT_KEY are required", file=sys.stderr)
        return 2

    tenant = os.environ.get("MLPEF_MCP_TENANT", "default")
    tool_names = [t.strip() for t in os.environ.get("MLPEF_MCP_TOOLS", _DEFAULT_TOOLS).split(",")
                  if t.strip()]
    transport = os.environ.get("MLPEF_MCP_TRANSPORT", "sse").lower()

    # Build the full enforcement pipeline in-process (fetches the public key, etc.).
    gateway = McpGateway(build_proxy(), agent_id=agent_id, credential=agent_key, tenant=tenant)
    server = _build_server(gateway, tool_names)
    init_options = _init_options(server)

    host = os.environ.get("MLPEF_MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("MLPEF_MCP_PORT", "9000"))
    if transport == "stdio":
        print(f"[mcp] MLPEF MCP gateway (stdio) as agent {agent_id}; tools={tool_names}",
              file=sys.stderr)
        _run_stdio(server, init_options)
    elif transport in ("streamable-http", "streamable_http", "http"):
        print(f"[mcp] MLPEF MCP gateway (streamable-http) on {host}:{port}/mcp as agent "
              f"{agent_id}; tools={tool_names}", file=sys.stderr)
        _run_streamable_http(server, host, port)
    else:
        print(f"[mcp] MLPEF MCP gateway (SSE) on {host}:{port}/sse as agent {agent_id}; "
              f"tools={tool_names}", file=sys.stderr)
        _run_sse(server, init_options, host, port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
