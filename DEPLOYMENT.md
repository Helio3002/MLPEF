# MLPEF — Setup, Operations & Production Guide

How to stand up MLPEF, register and govern agents, and harden it for real use.
For the *why* and the internals, see [`ARCHITECTURE.md`](ARCHITECTURE.md); for the
control→threat mapping and residual risks, see [`THREAT_MODEL.md`](THREAT_MODEL.md).

> **Posture reminder.** MLPEF is measurable defense-in-depth, **not** a guarantee.
> It can only enforce on tool calls that route through one of its ingress adapters —
> **traffic that bypasses the proxy is unguarded.** Nothing here claims total
> protection; every known gap is a numbered residual (R-n) in the threat model.

---

## 1. What you are deploying

| Component | Role | Default port | Image build |
|---|---|---|---|
| **postgres** | System of record (agents, profiles, tools, audit chain, HITL, nonces) | 5432 | `postgres:16-alpine` |
| **control-api** | Control plane: registration, profiles, HITL mint, audit store, RBAC | 8080 | `control-plane/control-api/Dockerfile` |
| **admin-ui** | React portal (talks only to control-api; reverse-proxies it under `/api`) | 8081 | `control-plane/admin-ui/Dockerfile` |
| **proxy** | Data plane: the 5-layer enforcement pipeline + REST/OpenAI ingress | 8090 | `data-plane/Dockerfile` |
| **mcp-gateway** *(profile `mcp`)* | Runnable MCP server fronting tools; governs MCP agents (no agent code) | 9000 | `data-plane/Dockerfile` |

**Control plane = config & visibility. Data plane = enforcement.** They are
separate services so the proxy scales horizontally and keeps enforcing (on cached,
*signed* config) even if the control plane is down.

---

## 2. Prerequisites

- Docker + Docker Compose v2 (`docker compose version`).
- For development outside containers: Python 3.12, Node 20.
- A way to hold secrets (a secret manager for production; `.env` for local/demo).

---

## 3. Quick start (single host / demo)

```bash
cp .env.example .env          # then edit every "change-me" value
docker compose up --build
```

- admin-ui → `http://localhost:8081` (log in with `MLPEF_ADMIN_*`)
- control-api → `http://localhost:8080` ( `/docs` for the OpenAPI explorer )
- proxy → `http://localhost:8090` ( `POST /v1/execute` )

The control-api container runs migrations → seeds (admin, deny-most default
profile, sample agent) → serves, all idempotent. The proxy fetches the HITL
**public** key from the control-api at boot and verifies every config bundle's
signature before applying it.

Drive the bundled agent (a denial is the system working):
```bash
docker compose --profile demo run --rm sample-agent
```

---

## 4. Production configuration

Everything is configured by environment variable. Treat **every** secret below as
something to generate fresh and inject from a secret manager — never commit it.

### 4.1 control-api

| Variable | Default | Production guidance |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./mlpef_control.db` | **Set to managed Postgres**: `postgresql+psycopg2://USER:PASS@HOST:5432/DB`. SQLite is dev-only. |
| `MLPEF_ADMIN_USERNAME` | `admin` | Use a named operator account. |
| `MLPEF_ADMIN_PASSWORD` | `admin` | **Set a strong password** (R-13). The seed warns if it is `admin`. The admin is seeded **once** — see §11. |
| `MLPEF_HITL_PRIVATE_KEY_PEM` | *(ephemeral)* | **Set a persistent Ed25519 PKCS8 PEM** from your secret manager (R-8/R-22). Unset = a new key each restart → tokens + config signatures stop verifying across restarts. |
| `MLPEF_SESSION_TTL_SECONDS` | `43200` (12h) | Shorten for tighter session expiry. |
| `MLPEF_HITL_TOKEN_TTL_SECONDS` | `300` | Keep approval tokens short-lived. |
| `MLPEF_AGENT_KEY_HEADER` | `X-Agent-Key` | The header agents present their API key in. |
| `MLPEF_CORS_ORIGINS` | `http://localhost:5173` | Only needed if the UI calls the API **cross-origin**. With the bundled same-origin nginx proxy it is unused (see §6). |
| `MLPEF_SAMPLE_AGENT_ID` / `_API_KEY` | *(unset)* | **Demo only.** When both set, the seed creates a fixed-credential sample agent (R-29). Leave unset in production. |

**Generate a real signing key:**
```bash
openssl genpkey -algorithm ed25519 -out hitl_signing_key.pem
# inject the file contents as MLPEF_HITL_PRIVATE_KEY_PEM (multi-line) via your
# orchestrator's secret→env (K8s/ECS preserve multi-line). Back it up + rotate.
```
The control plane is the **only** holder of this private key; proxies receive the
public key from `GET /hitl/public-key` and can *verify* tokens + config but never
*mint* them. Losing/leaking it ⇒ rotate immediately (an attacker who holds it can
mint approval tokens, R-8).

### 4.2 proxy (data plane)

| Variable | Default | Production guidance |
|---|---|---|
| `MLPEF_CONTROL_PLANE_URL` | `http://control-api:8080` | Internal URL of the control-api. |
| `MLPEF_CONFIG_TTL_SECONDS` | `30` | Config-bundle cache TTL (hot-reload window). |
| `MLPEF_HITL_PUBLIC_KEY_PEM` | *(fetched)* | Optionally pin the verification key instead of fetching it at boot. |
| `MLPEF_HITL_LEEWAY_SECONDS` | `0` | Clock-skew tolerance for token expiry (R-3). Keep 0 with synced clocks (NTP). |
| `MLPEF_AUDIT_URL` + `MLPEF_AUDIT_AGENT_KEY` | *(stdout)* | Set to POST audit events to the control-plane store so they show in the UI. |
| `MLPEF_NONCE_URL` + `MLPEF_NONCE_AGENT_KEY` | *(in-process)* | **Set for any multi-instance proxy fleet** so HITL single-use holds across instances (R-2). |
| `MLPEF_SANDBOX_ENABLED` | `false` | `true` enables real L3/L4 execution — requires a Docker socket (see §8). |
| `MLPEF_SANDBOX_IMAGE` / `_POOL_SIZE` | `alpine` / `2` | Sandbox base image + warm-pool size. |

### 4.3 admin-ui (build-time)

| Variable | Default | Notes |
|---|---|---|
| `VITE_API_BASE_URL` | `/api` | Baked at **build** time. `/api` = same-origin via the bundled nginx reverse proxy (recommended; no CORS). Only change to an absolute URL if you intentionally split origins. |

---

## 5. TLS (do this before exposing anything)

The compose stack speaks plain HTTP (R-31). Bearer tokens and agent API keys must
not traverse cleartext. **Terminate TLS at a reverse proxy / ingress in front of
every service** (nginx, Caddy, Traefik, an ALB, or a K8s Ingress) and route only
HTTPS to clients. Pair with HSTS and a CSP on the UI (reinforces R-11, the
localStorage token residual).

---

## 6. The UI ↔ API path (and why it "just works" remotely)

The admin-ui's nginx reverse-proxies the control-api under `/api`, so the browser
talks to **one origin** (port 8081): no CORS, and on hosts like GitHub Codespaces
a single forwarded port + "Continue" cookie covers the API too. To put the API on
a different origin instead, set `VITE_API_BASE_URL` to that absolute URL **and add
that origin to `MLPEF_CORS_ORIGINS`** — but same-origin is simpler and is the
default.

---

## 7. Database & migrations

Schema is managed by Alembic. The control-api container runs
`alembic upgrade head` on every start (idempotent), so deploys auto-migrate.
Manually:
```bash
cd control-plane/control-api && alembic upgrade head
```
Migrations live in `control-plane/control-api/alembic/versions/`
(`0001_initial` → `0002_audit` → `0003_hitl` → `0004_hitl_nonces`). Use a
**managed/HA Postgres** with backups in production (the audit chain is your
tamper-evident system of record).

---

## 8. Enabling real tool execution (the sandbox)

By default the proxy enforces L1/L2/L5 but does **not** execute tools (L3/L4 are
skipped, no Docker needed). To actually run code-executing tools (e.g.
`shell.exec`) in a hardened, ephemeral container with output filtering:

```bash
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up --build
```

That overlay sets `MLPEF_SANDBOX_ENABLED=true` and mounts the host Docker socket.
**The socket mount is privileged (host-root-equivalent) — R-30.** For production,
do **not** mount the raw host socket on a shared host. Prefer:
- a dedicated, isolated sandbox host / node pool,
- a rootless or remote Docker daemon, or
- a stronger isolation backend (gVisor / Firecracker) behind the same
  `SandboxBackend` interface (R-5).

Hardening applied to every sandbox container: read-only rootfs, all capabilities
dropped, `no-new-privileges`, non-root user, default seccomp (never disabled),
CPU/memory/PID cgroup limits, and **networking off by default** (egress allowlist
is R-24).

---

## 9. Scaling the proxy fleet

The proxy is stateless except for two caches; scale it horizontally behind a load
balancer. Two things you **must** configure for a fleet:

1. **Shared nonce ledger (R-2).** Set `MLPEF_NONCE_URL` + `MLPEF_NONCE_AGENT_KEY`
   so single-use HITL tokens are consumed in the control-plane Postgres ledger,
   not in per-process memory. Without this, an approved token could be replayed
   against a second instance.
2. **Config cache.** Each instance independently pulls + caches signed bundles
   (TTL `MLPEF_CONFIG_TTL_SECONDS`, last-known-good on control-plane outage). No
   shared state needed; expect up to one TTL of propagation delay on policy edits
   (R-6).

The control-api is also horizontally scalable, but the audit append path is a
single-writer concern at scale (R-16) — front it with one writer or serialize
appends.

---

## 10. Registering & managing agents

An agent is **registered once** and inherits a centrally-managed **policy
profile**; you never hand-configure an agent. New agents get the **deny-most
default profile** — they can do nothing until you grant capability.

### 10.1 Via the admin UI
1. **Agents → Register.** Enter a name (+ optional tenant/profile). The **API key
   is shown exactly once** — copy it now; only its SHA-256 hash is stored.
2. **Assign a profile** (or keep the locked-down default).
3. **Suspend / activate** to revoke or restore access. A suspended agent's config
   pull is rejected immediately (it stops working at the next cache refresh).

### 10.2 Via the API
```bash
# Log in (admin) → bearer token
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}' | jq -r .token)

# Register an agent (requires superadmin or security-reviewer)
curl -s -X POST http://localhost:8080/agents \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"billing-agent","tenant":"acme","profile_id":"default-locked-down"}'
# → { "id": "...", "api_key": "mlpef_...", ... }   # api_key shown ONCE

# Lifecycle
curl -X POST http://localhost:8080/agents/$ID/suspend  -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:8080/agents/$ID/activate -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:8080/agents/$ID/profile  -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"profile_id":"billing-readonly"}'
```

### 10.3 Pointing the agent at the proxy

The agent sends its calls to an **ingress adapter** on the proxy, presenting its
identity (`X-Agent-Id`) + API key (`X-Agent-Key`). The proxy resolves identity →
pulls that agent's signed profile → runs the 5 layers.

| Adapter | Endpoint (on the proxy) | Use for |
|---|---|---|
| **REST** | `POST /v1/execute` | any client; lowest common denominator |
| **OpenAI-compatible** | `POST /openai/v1/tool-calls` | drop-in for OpenAI tool/function-call loops |
| **MCP gateway** | embedded in an MCP server | Model Context Protocol agents (primary path) |
| **SDK shims** | in-process decorator / LangChain tool wrapper | governing a Python agent's own tools |

REST example:
```bash
curl -X POST http://localhost:8090/v1/execute \
  -H "X-Agent-Id: $AGENT_ID" -H "X-Agent-Key: $AGENT_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"tool":"fs.read","action":"fs.read","resource":"/work/data.txt",
       "arguments":{"path":"/work/data.txt"}}'
# 200 ALLOW / 403 DENY / 202 HITL_REQUIRED  (+ a coded reason)
```
A reference client is in `data-plane/ingress/examples/sample_agent.py`; per-adapter
integration notes are in `data-plane/ingress/README.md`.

> **Coverage = mandatory ingress.** If an agent can reach a tool *without* going
> through one of these adapters, MLPEF cannot govern that call (R-1). Enforce
> routing with network policy / egress lockdown so the proxy is the only path out.

### 10.4 No-code MCP integration (point an agent at MLPEF)

If your agent speaks **MCP** (Claude Desktop, Cline, Cursor, LangGraph via
`langchain-mcp-adapters`, …), you integrate by **configuration only** — no code.
MLPEF ships a runnable MCP gateway server that fronts your tools and enforces every
`tools/call` through the pipeline.

**1. Prepare (UI, no code):** register an agent (copy its API key), assign a profile
that allowlists the tools you want exposed, and register those tools.

**2. Run the gateway:**
```bash
# set the agent identity in .env (or reuse the demo agent):
#   MLPEF_SAMPLE_AGENT_ID / MLPEF_SAMPLE_AGENT_API_KEY  (or MLPEF_MCP_AGENT_ID/_KEY)
docker compose --profile mcp up --build
# → MCP gateway (SSE) at  http://localhost:9000/sse
```
Configure it with env (compose sets sensible defaults): `MLPEF_MCP_AGENT_ID`,
`MLPEF_MCP_AGENT_KEY`, `MLPEF_MCP_TOOLS` (comma-separated tool names),
`MLPEF_MCP_TRANSPORT` (`sse` default, or `stdio`), `MLPEF_MCP_PORT`.

**3. Point your agent at it (config only):**

- **URL/SSE clients** (Cline, Cursor, LangGraph) — add an MCP server with URL
  `http://<host>:9000/sse`.
  ```python
  # LangGraph / LangChain via langchain-mcp-adapters — zero tool code:
  from langchain_mcp_adapters.client import MultiServerMCPClient
  client = MultiServerMCPClient({"mlpef": {"url": "http://localhost:9000/sse",
                                           "transport": "sse"}})
  tools = await client.get_tools()      # already governed by MLPEF
  ```
- **stdio clients** (e.g. Claude Desktop's `mcpServers` config) — run the gateway
  in stdio mode by launching it with `MLPEF_MCP_TRANSPORT=stdio` and the agent
  env, e.g. a config entry that runs `python -m ingress.mcp_server` with
  `MLPEF_MCP_AGENT_ID` / `MLPEF_MCP_AGENT_KEY` / `MLPEF_CONTROL_PLANE_URL` set.

That's it — the agent's tool calls now flow `agent → MLPEF MCP gateway → pipeline`.
Denied calls come back as a readable `[mlpef:deny] …` tool message the model reads;
HITL-gated calls return the reason, and the agent retries with `approval_token`
once an operator approves in the UI.

> One gateway instance acts as **one** registered agent (MCP's basic transports
> carry no per-call credential). Run one gateway per agent identity, and still
> enforce that the agent can't reach tools except through it (R-1).

---

## 11. Resetting the seeded admin

The admin user is created on the **first** seed only; later changing
`MLPEF_ADMIN_PASSWORD` does **not** update an existing user. To rotate via re-seed
(destroys the DB volume — dev only):
```bash
docker compose down -v && docker compose up --build -d
```
In production, manage admin credentials/rotation through the DB or an added admin
endpoint rather than re-seeding.

---

## 12. Defining policy profiles

A profile is the reusable unit of capability. Editing one reconfigures **every**
agent on it (the UI shows the affected-agent count before save). Authored as JSON
(UI editor or `POST/PUT /profiles`). Shape (`common/profiles.py`):

```jsonc
{
  "profile_id": "billing-readonly",
  "name": "Billing (read-only)",
  "tenant": "acme",
  "version": 1,
  "tool_allowlist": ["fs.read", "http.get"],        // empty = nothing permitted
  "resource_scopes": [
    { "kind": "path", "jail_prefix": "/work", "allow_patterns": [] }
  ],
  "hitl_rules": [
    { "action_pattern": "fs.write", "resource_pattern": "*",
      "approver_roles": ["approver"], "token_ttl_seconds": 300 }
  ],
  "sandbox_limits": {                                // safe floor; widen deliberately
    "cpu_millicores": 500, "memory_mb": 256, "pids": 128, "timeout_seconds": 30,
    "read_only_rootfs": true, "drop_all_capabilities": true,
    "no_new_privileges": true, "run_as_non_root": true,
    "network_enabled": false, "egress_allowlist": []
  },
  "output_filter": {
    "scan_secrets": true, "secret_entropy_threshold": 4.0,
    "redact_pii": true, "neutralize_injection": true
  }
}
```

Profile-authoring principles:
- **Allowlist, never denylist.** An empty `tool_allowlist` permits nothing.
- **Least privilege.** Grant the narrowest tools + tightest path/URL scopes.
- **Gate destructive actions with HITL rules** (writes, deletes, spend, deploy).
- An over-broad allow is excessive agency (R-7) — review profile edits.

---

## 13. Registering tools

Tools must be known to be allowlisted. **Tools** page (or `PUT /tools/{name}`)
registers a tool name, its JSON argument schema, and a `default_allow` flag. The
proxy's Layer 1 validates each tool's argument *shapes* (paths get jailed,
commands stay argv-only, URLs structurally checked).

---

## 14. The HITL approval workflow

1. An agent attempts an action a profile marks `hitl_rules` → Layer 2 returns
   **HITL_REQUIRED** (HTTP 202); the call does **not** execute.
2. An `approver`/`superadmin` opens **HITL Queue** and approves → the control
   plane mints a **scoped, single-use, expiring** Ed25519 token.
3. The agent retries with that token (`approval_token`); Layer 2 verifies
   signature + exact scope + expiry + single-use nonce, then allows once.
4. Replays, scope mismatches, expiry, and forgery are denied **and** flagged as
   security events in the audit trail.

---

## 15. Audit & monitoring

- **Audit Explorer** — filter by agent/action/outcome; expand a record's full
  five-layer trace; **one-click chain verification** (recomputes the SHA-256
  hash-chain to prove no record was altered/dropped/reordered); export CSV/JSON.
- **Dashboard** — denial rate, blocked-attack counts (security events),
  decision-path p50/p99.
- **Integrity at scale.** The chain is tamper-**evident**, not tamper-**proof**
  (R-19): ship audit to append-only/WORM storage and publish periodic anchor
  hashes off-system for the strongest guarantee. Verify on a schedule.

---

## 16. Operations runbook

| Situation | Action |
|---|---|
| **Login fails / connection refused** | Confirm control-api is healthy (`docker compose ps`, `curl :8080/healthz`). On Codespaces, set port 8081 **Public** and click GitHub's "Continue" once (same-origin `/api` proxy covers the API). |
| **Agent suddenly denied everything** | Check it isn't suspended; check its profile's `tool_allowlist`; check the proxy can reach the control-api (else it serves last-known-good, then fails closed). |
| **HITL tokens stopped verifying after a restart** | `MLPEF_HITL_PRIVATE_KEY_PEM` is unset → ephemeral key changed. Set a persistent key (R-22). |
| **`ConfigBundleUntrusted` / config_untrusted denials** | The proxy's public key doesn't match the control-plane's signing key (key rotated, or impersonation). Re-fetch the key / re-pin; investigate if unexpected (it's a security event). |
| **Replays slipping through on a fleet** | `MLPEF_NONCE_URL` not set → per-process nonces. Point all proxies at the shared ledger (R-2). |
| **Sandbox won't start** | Enabled without a reachable Docker socket → the proxy fails closed at boot. Provide the socket (§8) or disable. |
| **Key rotation** | Generate a new Ed25519 key, roll it into the control-api secret, restart control-api, then restart/refresh proxies so they fetch the new public key. In-flight short-lived tokens expire naturally. |
| **Backups** | Back up Postgres (agents, profiles, **audit chain**, nonces). The audit chain is your evidence trail. |

---

## 17. Production-readiness checklist

- [ ] Managed Postgres in `DATABASE_URL`; automated backups; HA.
- [ ] Persistent `MLPEF_HITL_PRIVATE_KEY_PEM` from a secret manager; rotation plan (R-8).
- [ ] Strong `MLPEF_ADMIN_PASSWORD`; named operator accounts; least-privilege roles (R-13).
- [ ] TLS terminated in front of every service; HSTS + CSP on the UI (R-31, R-11).
- [ ] `MLPEF_SAMPLE_AGENT_*` **unset** (no fixed demo credential, R-29).
- [ ] Proxy fleet points at the shared nonce ledger (`MLPEF_NONCE_URL`, R-2).
- [ ] Audit goes to the store (`MLPEF_AUDIT_URL`) and ideally onward to WORM (R-19); scheduled chain verification.
- [ ] If sandbox enabled: isolated host + rootless/remote daemon or gVisor/Firecracker, **never** a shared host socket (R-30, R-5).
- [ ] Network policy so agents can only reach tools **through** the proxy (R-1).
- [ ] Clocks synced (NTP) across control plane + proxies (R-3).
- [ ] Read `THREAT_MODEL.md` end to end and accept/own each residual relevant to your deployment.

MLPEF reduces and *measures* risk; it does not eliminate it. Deploy it as one
deterministic control layer in a broader defense-in-depth program.
