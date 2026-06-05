# MLPEF — Multi-Layer Policy Enforcement Framework

MLPEF is a **deterministic Zero Trust platform that governs what autonomous AI
agents are allowed to do.** It intercepts every tool call an agent attempts and
runs it through five deterministic layers; a call executes only if all five pass,
otherwise it is denied and logged.

It has two planes:

- **Data plane — the Enforcement Proxy.** Intercepts tool calls and runs:
  `L1 Validate → L2 Policy → L3 Sandbox → L4 Filter → L5 Audit` (fail-closed).
- **Control plane — Central Management.** Register agents, define reusable policy
  profiles, approve human-in-the-loop (HITL) requests, and read the audit trail,
  via an admin web portal.

## What MLPEF does and does not claim

MLPEF is **measurable defense-in-depth, not a guarantee.** Please read these
three constraints — they govern the whole design:

1. **No total/“100%” protection.** We never claim guaranteed or unbreakable
   prevention. [`THREAT_MODEL.md`](THREAT_MODEL.md) maps every control to a threat
   (STRIDE + OWASP LLM Top 10) and logs every gap as a **residual risk with a
   severity**.

2. **Coverage depends on agents routing through MLPEF — it is not magic.** The
   proxy can only enforce on calls that transit one of its ingress adapters.
   **Traffic that bypasses the gateway is unguarded.** "Integrate with every AI
   agent" means we ship the broadest possible *mandatory ingress surface* (MCP
   gateway, OpenAI-compatible shim, REST, SDK shims) that all converge on one
   pipeline — not that MLPEF can govern an agent that never connects to it.

3. **Split latency budget — there is no single 10 ms end-to-end promise.**
   - **Decision path (L1 + L2):** target **< 10 ms p99**, via in-process
     validation + Rego compiled to WASM evaluated in-memory (no network hop on
     the hot path).
   - **Execution path (L3):** a *separate* budget served by a pre-warmed sandbox
     pool (target checkout **< 50 ms**). Docker cold-start is hundreds of ms; we
     never claim 10 ms for it.
   - Benchmarks are **measured, never fabricated** — real p50/p99 numbers land in
     this README in Phase 11.

## Core security model — "Assume Breach"

The LLM reasoning engine is treated as **fully attacker-controlled**. No
prompt/alignment guardrail is trusted. Every guarantee comes from deterministic
code in the proxy. We decouple the non-deterministic **Decide** phase (agent) from
the deterministic **Do** phase (proxy). The model's output is the *subject* of a
decision, never an *input* to one.

## Architecture

```
                ┌─────────────────────── CONTROL PLANE ───────────────────────┐
                │  admin-ui (React)  ──►  control-api (FastAPI)  ──►  Postgres │
                │   • register agents      • agents / profiles / tools         │
                │   • manage profiles      • HITL approval queue → token mint   │
                │   • approve HITL         • audit store + integrity verify     │
                │   • read audit/dashboards• RBAC (admin users)                 │
                └───────────────▲───────────────────────────┬──────────────────┘
                  config bundle  │ (pull + cache + hot-reload) │ HITL token
                                 │                             ▼
  AI agents ──ingress adapters──►│   DATA PLANE — Enforcement Proxy (scales out)
  (MCP / OpenAI-compat / REST /  │   L1 Validate → L2 Policy → L3 Sandbox →
   SDK shims)                    │   L4 Filter → L5 Audit   (fail-closed)
```

- **Control plane = config & visibility; data plane = enforcement.** Separate
  services so the proxy scales horizontally and stays available (last-known-good
  cached config) even if the UI is down.
- **Identity-driven config.** Each registered agent gets a credential; the proxy
  resolves identity → pulls the assigned policy profile (cached with TTL +
  invalidation, hot-reloaded). An agent is registered once and inherits a centrally
  managed profile — no per-agent manual configuration.

## Repository layout

```
mlpef/
  common/                 # shared Intent/Decision types, errors, timing, signed-token lib
  control-plane/
    control-api/          # FastAPI: agents, profiles, tools, HITL, audit, RBAC
    admin-ui/             # React/TS/Tailwind admin portal
    db/                   # SQLAlchemy models + Alembic migrations + seed
  data-plane/
    proxy/                # lifecycle, layer orchestration, identity, config cache
    ingress/              # mcp_gateway, openai_compat, rest, sdk_shims/
    layer1_validation/  layer2_policy/  layer3_sandbox/  layer4_filter/  layer5_audit/
  policies/               # .rego + WASM build artifacts + opa test suites
  tests/{unit,adversarial,bench}/
  THREAT_MODEL.md
  README.md
```

## Build status — phased, review-gated

Built in separate, reviewable phases (see the project charter). Each phase ends
with passing tests, an updated `THREAT_MODEL.md`, and real benchmarks where
applicable.

| Phase | Scope | Status |
|---|---|---|
| **1** | `common/` types + signed-token lib + `THREAT_MODEL.md` skeleton | **done** |
| **2** | Control plane core (DB, CRUD, registration, config bundle, seed) | **done** |
| **3** | L5 audit store + integrity verification | **done** |
| **4** | L1 validation + adversarial traversal/injection tests | **done** |
| **5** | L2 Rego + WASM + in-process evaluator + HITL wiring | **done** |
| **6** | L3 sandbox backend + hardening + warm pool | **done** |
| **7** | L4 output scanners + loop-injection stripping | **done** |
| **8** | Proxy orchestration + identity + config cache + e2e | **done** |
| **9** | Ingress adapters + integration docs + sample agent | **done** |
| **10** | Admin UI (RBAC-gated) | **done** |
| **11** | `docker-compose` full stack + benchmark harness (numbers from your run) | **done** |

### What Phase 1 delivers

- `common/` shared types: `Intent`, `LayerDecision`/`PipelineResult`, strict
  Pydantic models (`extra=forbid`, frozen), the `DenyReasonCode` taxonomy, and a
  fail-closed error → decision mapping.
- **HITL signed-token library** (`common/tokens.py`): Ed25519 mint (control
  plane) + deterministic verify (data plane) — scope-bound, single-use, expiring.
  The proxy holds the **public key only**, so a compromised proxy cannot mint.
- `PolicyProfile` / `ConfigBundle` schemas + a canonical **deny-most safe-default
  profile**.
- Unit + **adversarial** tests covering replay, Confused-Deputy scope misuse,
  cross-key forgery, tampering, and expiry.

## Developing (run in your environment / Codespace)

Requires Python 3.12.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,control,proxy]"

ruff check .          # lint (whole repo)
mypy                  # static types (strict, on common/)
pytest                # repo-root: common/ unit + adversarial tests
```

The control-api and data-plane carry their own test roots:

```bash
cd control-plane/control-api && alembic upgrade head && pytest   # API + audit store
cd data-plane && pytest                                          # Layer 5 emitter
```

> Service dependencies (the Docker sandbox SDK, OPA) and `docker compose up` for
> the full stack arrive in their respective phases.

## Running the full stack (docker-compose)

`docker compose` brings the whole platform up on one network — Postgres, the
control-api, the admin UI, and the data-plane proxy.

```bash
cp .env.example .env          # then edit every "change-me" secret
docker compose up --build
```

Default endpoints:

| Service | URL | Notes |
|---|---|---|
| admin-ui | `http://localhost:8081` | log in with `MLPEF_ADMIN_*` from `.env` |
| control-api | `http://localhost:8080` | FastAPI; `/docs` for the API |
| proxy (ingress) | `http://localhost:8090` | data plane; `POST /v1/execute` |

The control-api container migrates (`alembic upgrade head`), seeds (admin user,
deny-most default profile, sample agent), then serves — all idempotent across
restarts. The proxy fetches the HITL **public** verification key from the
control-api at startup (public key only — it can verify tokens, never mint them).

**Try the sample agent — a denial is the system working as intended:**

```bash
docker compose --profile demo run --rm sample-agent
```

On the seeded deny-most profile this call is **denied** (default-deny) and
audited (`docker compose logs proxy`). To see an allow, grant the tool to the
agent's profile in the UI (Policy Profiles → add `shell.exec` to `tool_allowlist`).

> **This is a dev/demo harness, not a production deployment.** Two deliberate
> limitations: the proxy runs with the **sandbox disabled** — L3/L4 are skipped,
> so only L1/L2/L5 enforce (THREAT_MODEL.md R-30) — and everything is plain HTTP
> with demo secrets (R-29, R-31). Change every secret and front it with TLS for
> anything real.

### GitHub Codespaces / remote hosts

The browser must reach the control-api directly, and `VITE_API_BASE_URL` is baked
into the UI **at build time**. On Codespaces, point both at the forwarded URLs and
make the control-api port **Public** (GitHub's private-port gateway strips the
CORS headers), then rebuild:

```bash
# in .env — use your forwarded hostnames
VITE_API_BASE_URL=https://<name>-8080.app.github.dev
MLPEF_CORS_ORIGINS=https://<name>-8081.app.github.dev

docker compose up --build     # --build is required: the API URL is compiled in
```

## Benchmarks

Per constraint #3, the latency budget is **split** and every number here is
**measured on your host, never fabricated**. The harness in `tests/bench/` prints
the table; paste your run's output into the cells below.

```bash
# Decision path (L1 Validate + L2 Policy) — target < 10 ms p99.
# Pure-Python, no services needed.
python tests/bench/bench_decision_path.py            # add --iters / --json as needed

# Sandbox warm-pool checkout (L3) — target < 50 ms checkout.
# Requires a reachable Docker daemon + a local image; skips cleanly without one.
python tests/bench/bench_sandbox.py                  # add --iters / --image / --json
```

What each scenario times (and what it deliberately excludes) is documented in the
script headers — e.g. HITL minting and ingress parsing are *not* on the measured
decision path; container cold-start is measured only to justify the warm pool, not
claimed as the request-path number.

**Decision path — `bench_decision_path.py`** (ms; lower is better):

| Scenario | Layers | p50 | p95 | p99 | max |
|---|---|---|---|---|---|
| `allow` (fs.read, jailed) | L1+L2 | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| `allow_hitl` (Ed25519 verify) | L1+L2 | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

**Sandbox — `bench_sandbox.py`** (ms; lower is better):

| Phase | p50 | p95 | p99 | max |
|---|---|---|---|---|
| `warm_checkout` (request-path) | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| `cold_create` (off-path, hidden by pool) | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

> _TBD_ cells stay until filled from an actual run. If a measured p99 misses its
> budget, that is recorded as a residual risk in `THREAT_MODEL.md` — we report the
> real number, we do not move the goalposts.
