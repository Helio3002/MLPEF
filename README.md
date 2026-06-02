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
| 4 | L1 validation + adversarial traversal/injection tests | pending |
| 5 | L2 Rego + WASM + in-process evaluator + HITL wiring | pending |
| 6 | L3 sandbox backend + hardening + warm pool | pending |
| 7 | L4 output scanners + loop-injection stripping | pending |
| 8 | Proxy orchestration + identity + config cache + e2e | pending |
| 9 | Ingress adapters + integration docs + sample agent | pending |
| 10 | Admin UI (RBAC-gated) | pending |
| 11 | `docker-compose` full stack + measured benchmarks | pending |

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
