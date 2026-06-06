# MLPEF — Agent Setup & Integration Guide

How to connect **any** AI agent so MLPEF governs its tool calls. Whatever your
agent speaks — MCP, OpenAI tool-calling, plain HTTP, or in-process Python — there
is a path here. For deployment/ops see [`DEPLOYMENT.md`](DEPLOYMENT.md); for the
internals see [`ARCHITECTURE.md`](ARCHITECTURE.md).

> **The one rule that makes this work (and the one honest limit).** MLPEF governs
> only the tool calls that **route through it**. There is no magic that intercepts
> an agent which never connects. "Works on every agent" means: for every agent
> there is an integration path below, and once the agent's tools run *through*
> MLPEF, every call is validated, policy-checked, sandboxed (optional), output-
> filtered, and audited. You must also ensure the agent **cannot reach its tools
> except through MLPEF** (network policy / egress lockdown) — otherwise that path
> is ungoverned (THREAT_MODEL.md R-1). MLPEF is defense-in-depth, not a guarantee.

---

## 0. The 30-second model

```
agent ──(MCP | OpenAI | REST | in-process)──► MLPEF ──► L1 Validate → L2 Policy →
                                                         L3 Sandbox → L4 Filter → L5 Audit
                                                         → ALLOW / DENY / HITL_REQUIRED
```
You **grant** capability centrally (a profile's tool allowlist), then **route** the
agent's tool calls through MLPEF. Denied calls come back as a readable message the
model can react to; gated calls wait for human approval.

**Two enforcement modes** (decide per tool):
- **Decision mode** — MLPEF runs L1+L2 and returns `ALLOW`/`DENY`/`HITL_REQUIRED`;
  *your tool* does the work on `ALLOW`. Best for tools that call APIs/DBs/files.
- **Execution mode** — for code-running tools (`shell.exec`) with the sandbox on,
  MLPEF runs the tool in a hardened container (L3) and returns the filtered output
  (L4). Your tool just returns that output.

---

## 1. Prerequisite for every path (do this once, no code)

### 1a. Register the agent → get its credential
**Admin UI → Agents → Register** (or API). The **API key is shown once.**
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)

curl -s -X POST http://localhost:8080/agents \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"billing-agent","tenant":"acme"}'
# → { "id": "<AGENT_ID>", "api_key": "mlpef_<KEY>", ... }   (api_key shown ONCE)
```

### 1b. Register the tools the agent may use
**Tools** page (or `PUT /tools/{name}`): a name + JSON arg schema per tool, e.g.
`fs.read`, `fs.write`, `http.get`, `shell.exec`. L1 validates argument shapes.

### 1c. Author a profile that allowlists those tools, and assign it
**Policy Profiles** (JSON editor) or `POST /profiles`. Empty allowlist = nothing
permitted. Add `hitl_rules` for actions that need human approval. Then assign the
profile to the agent. (Full profile shape: `DEPLOYMENT.md` §12.)

> New agents start on the **deny-most default** — they can do nothing until you
> grant tools here. A first `DENY` is the system working.

---

## 2. Which path should I use?

| Your agent… | Use | Code? |
|---|---|---|
| speaks **MCP** (Claude Desktop, Cline, Cursor, Continue, LangGraph+mcp-adapters) | **§3 MCP gateway** | **none** (config only) |
| runs an **OpenAI tool/function-calling** loop | **§4 OpenAI shim** | minimal |
| is **custom / any HTTP** client | **§5 REST** | thin client |
| is a **Python** app you control (LangGraph/CrewAI/AutoGen/custom) | **§5 REST** wrapper, or **§6 in-process shim** | small wrapper |

When in doubt: **§5 REST** works for literally any agent that can make an HTTP call.

---

## 3. MCP agents — no-code (recommended)

MLPEF ships a **runnable MCP gateway server** that fronts your tools. Point your
MCP agent at it; every `tools/call` is enforced. No agent code changes.

### 3a. Run the gateway
```bash
# .env already has the demo agent; or set MLPEF_MCP_AGENT_ID/_KEY to your agent.
docker compose --profile mcp up --build
```
It supports **all three MCP transports** (pick with `MLPEF_MCP_TRANSPORT`):

| Transport | `MLPEF_MCP_TRANSPORT` | Endpoint | Use with |
|---|---|---|---|
| **SSE** (default) | `sse` | `http://<host>:9000/sse` | most current URL-based clients |
| **Streamable HTTP** | `streamable-http` | `http://<host>:9000/mcp` | newer clients that require it |
| **stdio** | `stdio` | (client spawns the process) | Claude Desktop classic, local clients |

Config env: `MLPEF_MCP_AGENT_ID`, `MLPEF_MCP_AGENT_KEY`, `MLPEF_MCP_TENANT`,
`MLPEF_MCP_TOOLS` (comma-separated, must match your profile's allowlist),
`MLPEF_MCP_PORT`, `MLPEF_CONTROL_PLANE_URL`. One gateway = one agent identity
(R-32): run one per agent and restrict its port to that agent.

### 3b. Point your client at it (config only)

**Cline / Cursor / Continue / generic URL client** — add an MCP server:
```jsonc
{
  "mcpServers": {
    "mlpef": { "url": "http://localhost:9000/sse" }   // or .../mcp for streamable-http
  }
}
```

**LangGraph / LangChain** (via `langchain-mcp-adapters`) — your graph's tools come
from MLPEF, already governed, with no per-tool code:
```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "mlpef": {"url": "http://localhost:9000/sse", "transport": "sse"},
})
tools = await client.get_tools()                 # governed MLPEF tools
agent = create_react_agent("anthropic:claude-3-5-sonnet-latest", tools)
# every tool the graph calls now flows agent → MLPEF gateway → L1..L5
```

**Claude Desktop / stdio clients** — the client launches the server itself, so it
needs a local install (`pip install -e ".[proxy]"`) and the control-api reachable:
```jsonc
{
  "mcpServers": {
    "mlpef": {
      "command": "python",
      "args": ["-m", "ingress.mcp_server"],
      "cwd": "/path/to/MLPEF/data-plane",
      "env": {
        "MLPEF_MCP_TRANSPORT": "stdio",
        "PYTHONPATH": "/path/to/MLPEF/data-plane",
        "MLPEF_CONTROL_PLANE_URL": "http://localhost:8080",
        "MLPEF_MCP_AGENT_ID": "billing-agent",
        "MLPEF_MCP_AGENT_KEY": "mlpef_<KEY>",
        "MLPEF_MCP_TOOLS": "fs.read,http.get"
      }
    }
  }
}
```

---

## 4. OpenAI tool/function-calling agents

Route the model's `tool_calls` through the shim and feed the returned `tool`
messages back. Denied calls return a readable `[mlpef:deny] …` message.
```python
import httpx
PROXY, AGENT_ID, AGENT_KEY = "http://localhost:8090", "<AGENT_ID>", "mlpef_<KEY>"

def govern_tool_calls(tool_calls: list[dict]) -> list[dict]:
    r = httpx.post(f"{PROXY}/openai/v1/tool-calls",
        headers={"X-Agent-Id": AGENT_ID, "X-Agent-Key": AGENT_KEY},
        json={"tool_calls": tool_calls}, timeout=15.0)
    return r.json()["tool_messages"]   # [{tool_call_id, role:"tool", content}]
# send these tool messages back to the model as the tool results
```
Each `tool_call` is `{"id","function":{"name","arguments":"<json-string>"}}` (the
exact shape OpenAI emits).

---

## 5. Any agent — plain REST

The lowest common denominator. Anything that can POST JSON can be governed.
```bash
curl -X POST http://localhost:8090/v1/execute \
  -H "X-Agent-Id: <AGENT_ID>" -H "X-Agent-Key: mlpef_<KEY>" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"fs.read","action":"fs.read","resource":"/work/data.txt",
       "arguments":{"path":"/work/data.txt"}}'
# 200 allow · 202 hitl_required · 403 deny
# body: {verdict, reason_code, reason, output, correlation_id, security_event}
```
A reusable Python wrapper for a LangGraph/custom agent (decision mode):
```python
import httpx
PROXY, AGENT_ID, AGENT_KEY = "http://localhost:8090", "<AGENT_ID>", "mlpef_<KEY>"
class GovernanceDenied(RuntimeError): ...

def gate(tool, action, resource, arguments, approval_token=None) -> str:
    b = httpx.post(f"{PROXY}/v1/execute",
        headers={"X-Agent-Id": AGENT_ID, "X-Agent-Key": AGENT_KEY},
        json={"tool": tool, "action": action, "resource": resource,
              "arguments": arguments, "approval_token": approval_token},
        timeout=10.0).json()
    if b["verdict"] != "allow":
        raise GovernanceDenied(f'{b["verdict"]} [{b.get("reason_code")}]: {b["reason"]}')
    return b["output"]      # non-empty only in execution mode

# wrap each tool: call gate(...) first, then do the work (decision mode)
def read_file(path: str) -> str:
    gate("fs.read", "fs.read", resource=path, arguments={"path": path})
    return open(path).read()
```
Reference client: `data-plane/ingress/examples/sample_agent.py`.

---

## 6. In-process Python agents (SDK shims)

If your agent **and** a `Proxy` instance run in the same Python process, use the
shipped shims (no HTTP):
```python
from ingress import governed, GovernedTool, GovernanceDenied

@governed(proxy, agent_id="<AGENT_ID>", credential="mlpef_<KEY>", tool="shell.exec")
def run_shell(argv): ...                      # raises GovernanceDenied unless ALLOWed

tool = GovernedTool(name="fs.read", description="read a file", func=read_file,
                    handler=proxy, agent_id="<AGENT_ID>", credential="mlpef_<KEY>",
                    resource_key="path")
tool.run(path="notes.txt")                    # enforced, then calls read_file
```
(Most deployments run the proxy as a separate service and use §3–§5 instead.)

---

## 7. Human-in-the-loop (HITL) retries

If a call returns `hitl_required` (HTTP 202 / `[mlpef:...]` message), it did **not**
run. Flow:
1. An `approver`/`superadmin` approves it in the admin UI **HITL Queue**.
2. The control plane mints a **scoped, single-use, expiring** token.
3. The agent **retries the same call** with `approval_token=<token>` (REST/SDK
   field, or as a tool argument) and it executes once.

In LangGraph this maps cleanly to an interrupt/checkpoint that resumes with the
token supplied.

---

## 8. Verify it's actually governed

1. Drive one tool call from your agent.
2. Admin UI → **Audit Explorer**: the call appears with its five-layer trace;
   click **verify chain**.
3. Try a tool that's **not** in the profile allowlist → expect `DENY`
   (`policy_default_deny`). That denial is proof enforcement is live.
4. Dashboard shows denial rate / blocked-attack counts / decision-path p50/p99.

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Every call `DENY` `unknown_tool` | The tool isn't in the agent's profile allowlist (or not registered). Grant it in the UI. |
| Every call `DENY` `policy_default_deny` | Profile allows the tool but a rule didn't match / it's deny-by-default. Check the profile. |
| `401` from the proxy | Bad/missing `X-Agent-Key`, or the agent is suspended. |
| MCP client can't connect | Wrong transport: try `MLPEF_MCP_TRANSPORT=streamable-http` (URL `/mcp`) vs `sse` (URL `/sse`); confirm port 9000 reachable. |
| MCP gateway container restarts | `MLPEF_MCP_AGENT_KEY` unset → it exits. Set the agent key in `.env`. |
| `hitl_required` never proceeds | Approve it in the UI, then retry the call **with** `approval_token`. |
| Allowed but empty `output` | Decision mode (sandbox off) — your code runs the tool. For real execution enable the sandbox (`DEPLOYMENT.md` §8). |
| `config_untrusted` / `ConfigBundleUntrusted` | Proxy's verification key ≠ control-plane signing key. Re-fetch/pin the key. |

---

## 10. Honest limits (read these)

- **Bypass = unguarded.** If the agent can call a tool without going through MLPEF,
  that call is not governed. Enforce routing (R-1).
- **MCP gateway = one agent, no per-connection auth** — network-restrict its port;
  run one per identity (R-32).
- **Output filtering and injection neutralization are heuristic** (R-4, R-26) — the
  durable guarantee is that injected text still can't drive a tool past the L1
  allowlist + L2 default-deny.
- **No "100%."** MLPEF is one deterministic, auditable enforcement layer in a
  broader defense-in-depth program. Every known gap is a numbered residual in
  `THREAT_MODEL.md`.
