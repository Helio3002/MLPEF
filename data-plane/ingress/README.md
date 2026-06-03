# Ingress adapters (universal integration)

Every adapter does the same thing: **normalize its native input into a `common.Intent`
and submit it to the identical five-layer pipeline** (via a `GovernedHandler` — the
proxy). They differ only in the wire format they speak.

> **Coverage = mandatory ingress, not magic.** MLPEF can only enforce on calls that
> transit one of these adapters. **Traffic that bypasses the gateway is unguarded.**
> In production, force agents through an adapter with network policy / egress lockdown.
> (THREAT_MODEL.md R-1.)

All adapters take an injected handler, so they're wired to a real `Proxy` at startup
and unit-tested with a fake handler.

## 1. MCP gateway (`mcp_gateway.py`) — primary path

MLPEF sits between an MCP-capable agent and downstream MCP tool servers. Mount the
gateway inside your MCP server's `tools/call` handler; any MCP agent is then governed
with **zero code changes**. Returns MCP's `CallToolResult` shape (`content` + `isError`).

```python
from ingress import McpGateway

gateway = McpGateway(proxy, agent_id="agent-1", credential=API_KEY)

# inside your MCP server's call_tool(name, arguments):
result = gateway.call_tool(name, arguments)   # {"isError": bool, "content": [...]}
```
The MCP transport (stdio / SSE / WebSocket) is provided by your MCP server.

## 2. OpenAI-compatible shim (`openai_compat.py`)

Drop-in for the OpenAI tool/function-calling ecosystem. `POST /openai/v1/tool-calls`
accepts OpenAI-style `tool_calls`; denied calls return a `[mlpef:...]` `tool` message
the model reads instead of the tool result.

```
POST /openai/v1/tool-calls
Headers: X-Agent-Id, X-Agent-Key
Body: {"tool_calls": [{"id": "...", "function": {"name": "...", "arguments": "{...}"}}]}
-> {"tool_messages": [{"tool_call_id": "...", "role": "tool", "content": "..."}]}
```

## 3. Plain REST (`rest.py`) — lowest common denominator

`POST /v1/execute` for any custom agent. Verdict maps to HTTP status:
`allow → 200`, `hitl_required → 202`, `deny → 403`.

```
POST /v1/execute
Headers: X-Agent-Id, X-Agent-Key
Body: {"tool": "...", "action": "...", "resource": "...", "arguments": {...},
       "approval_token": "<optional, for HITL retries>"}
-> {"verdict", "reason_code", "reason", "output", "correlation_id", "security_event"}
```
See `examples/sample_agent.py`.

## 4. SDK shims (`sdk_shims/`) — reference wrappers

A generic decorator and a LangChain-style tool wrapper for in-process agents.

```python
from ingress import governed, GovernedTool, GovernanceDenied

@governed(proxy, agent_id="agent-1", credential=API_KEY, tool="shell.exec")
def run_shell(argv): ...        # raises GovernanceDenied unless ALLOWed

tool = GovernedTool(name="fs.read", description="read a file", func=read_file,
                    handler=proxy, agent_id="agent-1", credential=API_KEY,
                    resource_key="path")
tool.run(path="notes.txt")      # enforced, then calls read_file
```

## HITL retries

When the pipeline returns `hitl_required`, an approver acts in the admin UI; the
control plane mints a scoped, single-use token. Re-submit the same call with that
token (`approval_token` field / argument) to proceed.
