# MLPEF — Architecture & Project Deep-Dive

The complete mental model of MLPEF: what it is, why it's built this way, how a
request flows end to end, what every layer and module does, and where each piece
lives. Read this to understand the project inside out. For *running* it see
[`DEPLOYMENT.md`](DEPLOYMENT.md); for the formal control↔threat mapping see
[`THREAT_MODEL.md`](THREAT_MODEL.md).

---

## 1. The one-paragraph thesis

**MLPEF governs what autonomous AI agents are allowed to *do*.** It treats the LLM
as **fully attacker-controlled** ("Assume Breach") and refuses to let any model
output be a *control signal*. It intercepts every tool call an agent attempts and
runs it through **five deterministic layers**; the call executes only if all five
pass, otherwise it is denied and logged. The non-deterministic **Decide** phase
(the agent/LLM) is decoupled from the deterministic **Do** phase (the proxy): the
model's output is the *subject* of a decision, never an *input* to one.

If you remember five things:
1. **Deterministic code makes every guarantee** — never a prompt or alignment.
2. **Fail-closed everywhere** — any error/timeout/ambiguity becomes a logged deny.
3. **Allowlist, default-deny** — nothing is permitted until explicitly granted.
4. **Coverage = mandatory ingress** — calls that bypass the proxy are unguarded.
5. **No "100%" claims** — every gap is a numbered residual risk with a severity.

---

## 2. The three non-negotiable constraints

These govern the whole design (and all UI/marketing copy):
1. **No total/"100%" protection.** Measurable defense-in-depth; every control maps
   to a threat (STRIDE + OWASP LLM Top 10) and every gap is a residual with a
   severity in `THREAT_MODEL.md`.
2. **Coverage depends on routing through MLPEF.** The proxy enforces only on calls
   that transit an ingress adapter. The value proposition is the *broadest
   mandatory ingress surface* (MCP / OpenAI-compat / REST / SDK shims) all
   converging on one pipeline — not magic that governs an agent that never connects.
3. **Split latency budget.** Decision path (L1+L2) targets **<10 ms p99** (in-process,
   no network hop). Sandbox (L3) is a *separate* budget (warm-pool checkout
   <50 ms; cold container start is hundreds of ms). Benchmarks are **measured,
   never fabricated** (see the README Benchmarks table).

---

## 3. The two planes

```
        ┌─────────────────── CONTROL PLANE (config & visibility) ──────────────────┐
        │  admin-ui (React) ──/api──► control-api (FastAPI) ──► Postgres            │
        │   • register agents       • agents / profiles / tools                    │
        │   • author profiles       • HITL approval queue → Ed25519 token mint      │
        │   • approve HITL          • signed config bundle + audit store + verify   │
        │   • read audit/dashboards • RBAC (admin users), single-use nonce ledger   │
        └───────────────▲────────────────────────────────────┬─────────────────────┘
          signed config  │ (pull + cache + verify + hot-reload) │ HITL token (verify only)
          + public key    │                                     ▼
  AI agents ─ingress──►   │   DATA PLANE — Enforcement Proxy (scales out, stateless-ish)
  (MCP / OpenAI /         │   L1 Validate → L2 Policy → L3 Sandbox → L4 Filter → L5 Audit
   REST / SDK shims)      │   (fail-closed; unskippable audit)
```

- **Why split?** The proxy must stay fast and available even if the UI/control
  plane is down — so it caches **signed** config (last-known-good) and holds only
  the **public** key (it can verify, never mint). The control plane owns all state
  and secrets.
- **Identity-driven config.** Each agent has a credential; the proxy resolves
  identity → pulls that agent's assigned profile as a signed `ConfigBundle` →
  caches it (TTL + invalidation + hot-reload). Edit the profile once, every agent
  on it reconfigures.

---

## 4. A request's journey (end to end)

A single tool call, traced through the system:

1. **Agent → ingress adapter** (e.g. `POST /v1/execute` with `X-Agent-Id` +
   `X-Agent-Key`). The adapter normalizes the native request into a canonical
   **`Intent`** (frozen, `extra="forbid"` Pydantic) and submits it to the Proxy.
   *The Intent is the subject of a decision; nothing in it is trusted to make one.*
2. **Identity + config (proxy).** `Proxy.handle` asks the `ConfigCache` for the
   agent's `ConfigBundle` (HTTP pull → **signature verified** → cached). A
   bad/revoked credential → `IdentityUnresolved`; control plane unreachable with no
   cache → `ConfigUnavailable`; an unsigned/forged bundle → `ConfigBundleUntrusted`.
   Any of these → deny + audit, never reach the layers (fail-closed).
3. **L1 Validate** — allowlist + shape + jail (in-process, I/O-free).
4. **L2 Policy** — default-deny ABAC; HITL-token verification if required.
5. **L3 Sandbox** — only for code-executing tools; warm, hardened, ephemeral container.
6. **L4 Filter** — scan/redact the tool's output; neutralize injection.
7. **L5 Audit** — **unskippable**, fail-closed, hash-chained record of the whole trace.
8. **Response** — `ALLOW` (200, output) / `DENY` (403) / `HITL_REQUIRED` (202),
   each with a stable `DenyReasonCode` and the five-layer trace recorded.

The pipeline stops at the **first non-allow** and then **always** writes the audit
record. If the audit write fails, the whole call fails closed (deny, no output)
even if the layers allowed — auditing is not optional.

---

## 5. The five layers in depth

Source: `data-plane/layer1_validation/ … layer5_audit/`. Each layer returns a
`LayerDecision`; an exception never escapes a layer — it becomes a coded deny.

### L1 — Validate (`layer1_validation/`)
Deterministic, **no-I/O** input validation so it stays on the <10 ms hot path.
- **Allowlist-first:** an unknown tool or unexpected argument is denied
  (`UnknownTool` / `UnknownField`).
- **Per-tool argument *shapes*** (`specs.py`): each argument has a *kind* —
  `path` (lexically canonicalized + jailed), `command` (argv-only, allowlisted
  program — never a shell string), `url` (structural http(s) check), `literal`
  (no metacharacters), `text` (only NUL rejected).
- **Path jail is lexical** (collapses `..`, rejects encoding/backslashes/NUL) — it
  does *not* resolve symlinks; true containment is L3's job (R-20).
- Threats: traversal, command/argument injection, schema abuse.

### L2 — Policy (`layer2_policy/`)
The **default-deny ABAC core**, mirrored by `policies/authz.rego` (a WASM-compiled
Rego module can slot behind the same `PolicyEngine` interface; the native engine is
the source of truth today — keeping them in sync is R-23).
- `classify` → `ALLOW` / `DENY` / `HITL_REQUIRED`. Tool not in the profile
  allowlist → deny floor. A matching `hitl_rule` → HITL_REQUIRED.
- **HITL enforcement:** if HITL_REQUIRED and a token is present, verify it
  (signature → expiry → exact scope → single-use nonce, in that order). Scope
  mismatch / replay / forgery / expiry are coded denies, and the abuse ones are
  flagged security events.

### L3 — Sandbox (`layer3_sandbox/`)
Ephemeral, hardened, **single-use** execution for code-running tools.
- `SandboxBackend` interface (Docker reference impl; gVisor/Firecracker can swap in,
  R-5). Hardening: read-only rootfs, all caps dropped, `no-new-privileges`,
  non-root, default seccomp, cgroup CPU/mem/PID limits, **network off** by default.
- **Warm pool** pre-creates containers so checkout is fast (the <50 ms budget);
  cold start (~hundreds of ms) is kept off the request path. A checked-out sandbox
  is used once and destroyed — never reused.
- In the default proxy build the sandbox is **off** (the command builder returns
  `None`); enable it with `MLPEF_SANDBOX_ENABLED=true` + a Docker socket (R-30).

### L4 — Filter (`layer4_filter/`)
Output is **untrusted data, never a control channel.**
- Scanners: secret detection (pattern + Shannon-entropy), PII redaction.
- **Injection neutralization:** neutralizes tool-output content that resembles
  instructions to the agent. This is heuristic (regex markers) — novel
  phrasings can evade it (R-26). The *durable* guarantee is upstream: injected text
  still cannot drive a tool call past the L1 allowlist + L2 default-deny.

### L5 — Audit (`layer5_audit/` + `common/audit.py`)
Tamper-**evident**, hash-chained, **unskippable**.
- The emitter builds an `AuditEvent` (who/what/resource/decision/reason/timestamp +
  full five-layer trace) and pushes it to a sink (stdout, or HTTP→control store).
- The control-plane store seals each event into an `AuditRecord` with `seq` +
  `prev_hash` + SHA-256 `record_hash` over the prior hash — altering, dropping, or
  reordering any record breaks the chain and is caught by `verify_chain`.
- Tamper-evident ≠ tamper-proof (R-19): pair with WORM storage + off-system anchors.

---

## 6. The control plane in depth (`control-plane/control-api/`)

FastAPI + SQLAlchemy 2.0 + Alembic. App factory `app/main.py` (`app.main:app`).

**Persistence (`app/models.py`):** `AdminUser`, `AdminSession`, `PolicyProfileRow`
(stores the full `common.PolicyProfile` as JSON + mirrored scalars), `Agent`
(credential stored as SHA-256 hash; plaintext shown once), `Tool`, `AuditRecordRow`
(the sealed chain), `HITLRequestRow`, `HitlNonceRow` (shared single-use ledger).

**Auth & RBAC (`app/deps.py`):**
- Admins: password login (`POST /auth/login`) → session **bearer token**; every
  request sends `Authorization: Bearer …`. Roles: `read-only` (view),
  `security-reviewer`/`superadmin` (edit agents/profiles/tools),
  `approver`/`superadmin` (HITL approve), `superadmin` (delete profiles).
- Agents/proxy: authenticate with the agent **API key** (`X-Agent-Key`) for the
  config-bundle pull, audit ingest, and nonce consume.

**Key endpoints:**
| Area | Endpoints |
|---|---|
| Auth | `POST /auth/login`, `GET /auth/me` |
| Agents | `POST /agents`, `GET /agents`, `GET /agents/{id}`, `POST /agents/{id}/{suspend,activate,profile}`, `GET /agents/{id}/config-bundle` |
| Profiles | `GET/POST /profiles`, `GET/PUT/DELETE /profiles/{id}`, `GET /profiles/{id}/impact` |
| Tools | `GET /tools`, `PUT /tools/{name}`, `DELETE /tools/{name}` |
| HITL | `POST/GET /hitl/requests`, `POST /hitl/requests/{id}/{approve,deny}`, `GET /hitl/public-key` (public), `POST /hitl/consume-nonce` |
| Audit | `POST /audit` (agent), `GET /audit`, `GET /audit/verify` (admin) |

**Config bundle (`crud.build_config_bundle`):** assembles the agent's profile +
`etag`/`version`, then **Ed25519-signs** it (`common.sign_config_bundle`) so the
proxy can authenticate it. The config-bundle endpoint enforces that an agent may
only pull *its own* bundle.

**HITL mint (`crud.approve_hitl_request`):** creates a random `jti`, mints a scoped
token (`common.mint_hitl_token`) bound to subject/tenant/action/resource with a
short TTL, and records the jti.

**Admin UI (`control-plane/admin-ui/`):** React + Vite + TS + Tailwind. Talks
**only** to the control-api; nginx reverse-proxies it under `/api` for same-origin
(no CORS). Pages: Agents, Policy Profiles (JSON editor + affected-agent count),
Tools, HITL Queue, Audit Explorer (filters, five-layer trace, chain verify,
CSV/JSON export), Dashboard (denial rate, blocked-attack counts, decision p50/p99).
Session token lives in `localStorage` (R-11).

---

## 7. The data plane in depth (`data-plane/`)

- **`proxy/proxy.py`** — `Proxy.handle(intent, credential)`: resolve config →
  run pipeline; identity/config failures deny + audit before the layers.
- **`proxy/config_cache.py`** — per-agent TTL cache; last-known-good on outage;
  evicts on `IdentityUnresolved`; fails closed (`ConfigUnavailable`) with no cache.
- **`proxy/http_config.py`** — pulls the bundle; **verifies its signature** when
  given the public key (refuses unsigned/forged config, R-12).
- **`proxy/pipeline.py`** — orchestrates L1→L4, stops at first non-allow, then the
  unskippable L5; maps a `command_builder` (which tools execute code).
- **`proxy/nonce_store.py`** — `HttpNonceStore`: consumes single-use nonces via the
  control-plane ledger for fleet-wide single-use (R-2); in-memory is the default.
- **`proxy/builder.py`** — `build_proxy()`: assembles the Proxy from env (fetch
  public key, signed-config cache, audit sink, nonce store, sandbox policy). No
  import-time side effects, so both entrypoints reuse it.
- **`proxy/server.py`** — the HTTP entrypoint (`uvicorn proxy.server:app`):
  `create_app(build_proxy())`, serving the REST + OpenAI ingress.
- **`ingress/`** — `base.py` (the canonical `Intent` builder + `GovernedHandler`
  protocol), `rest.py` (`/v1/execute`), `openai_compat.py` (`/openai/v1/tool-calls`),
  `mcp_gateway.py` (the `McpGateway` enforcement core) + `mcp_server.py` (a
  **runnable** MCP server over stdio/SSE for no-code MCP integration),
  `sdk_shims/` (decorator + LangChain wrapper). **Every adapter produces the same
  `Intent` and hits the identical pipeline.**

---

## 8. The cryptography

Three independent uses of Ed25519 / SHA-256, all in `common/` so the control plane
and proxy share exact definitions:

| Use | Signs | Verifies | Module | Why |
|---|---|---|---|---|
| **HITL approval tokens** | control plane (private key) | proxy (public key) | `common/tokens.py` | A compromised proxy can't *mint* approvals; tokens are scope-bound, single-use (nonce), expiring. Domain tag `MLPEF-HITL-token-v1`. |
| **Config bundles** | control plane | proxy | `common/config_signing.py` | The proxy authenticates config, not just TLS (R-12). Distinct domain tag `MLPEF-config-bundle-v1` so a config sig can't be replayed as a token. |
| **Audit chain** | control-plane store (hash chain) | anyone (`verify_chain`) | `common/audit.py` | Tamper-evidence: each `record_hash` covers the prior hash. |

**Key custody:** the control plane holds the **one** Ed25519 private key
(`MLPEF_HITL_PRIVATE_KEY_PEM`, or ephemeral in dev). Proxies fetch the **public**
key from `GET /hitl/public-key` at boot. Verification is deterministic; the nonce
is consumed **last** (so a scope-mismatched token never burns the legit holder's
single use).

---

## 9. The shared contract (`common/`)

Dependency-light, framework-free types both planes import (so they never drift). It
is the only package under `mypy --strict`.

- `intent.py` — `Intent` (the normalized tool call) + `Provenance`.
- `decision.py` — `LayerDecision` (+ `from_error` fail-closed mapping),
  `PipelineResult.from_layers`.
- `enums.py` — `Verdict`, `LayerName`, `IngressSource`, `Severity`, and the
  `DenyReasonCode` taxonomy (the stable audit/dashboard vocabulary).
- `errors.py` — the `MLPEFError` hierarchy; each error carries a fixed
  `reason_code` / `layer` / `security_event` so error→decision is auditable.
- `profiles.py` — `PolicyProfile`, `ConfigBundle`, `SandboxLimits`,
  `ResourceScope`, `HITLRule`, `OutputFilterPolicy`, `default_locked_down_profile`.
- `tokens.py` — HITL mint/verify + `NonceStore` protocol + `InMemoryNonceStore`.
- `config_signing.py` — `sign_config_bundle` / `verify_config_bundle`.
- `audit.py` — `AuditEvent` / `AuditRecord` / `seal_event` / `verify_chain`.
- `timing.py` — `Stopwatch`, `now_epoch`, `monotonic_ms`, `PhaseTimings`.

All models are `extra="forbid"` + frozen — a malformed or padded request is
rejected at construction, not silently carried forward.

---

## 10. Repository map

```
mlpef/
  common/                  # shared types, crypto, errors, timing  (mypy --strict)
  control-plane/
    control-api/app/       # FastAPI: config.py db.py models.py security.py deps.py
                           #          crud.py signing.py schemas.py main.py routers/*
    control-api/alembic/   # migrations 0001..0004
    admin-ui/src/          # React: api/ auth/ components/ pages/  (+ nginx.conf, Dockerfile)
  data-plane/
    proxy/                 # proxy, pipeline, config_cache, http_config, nonce_store, server
    ingress/               # base, rest, openai_compat, mcp_gateway, sdk_shims/, examples/
    layer1_validation/ … layer5_audit/
  policies/                # authz.rego + opa tests
  tests/{unit,adversarial,bench}/   # repo-root: common tests + benchmark harness
  docker-compose.yml + docker-compose.sandbox.yml + .env.example
  README.md  DEPLOYMENT.md  ARCHITECTURE.md  THREAT_MODEL.md
```
(The control-api and data-plane each carry their own test roots too.)

---

## 11. How it was built (phases + hardening)

Built in 11 review-gated phases, each ending with passing tests, a `THREAT_MODEL`
update, and real benchmarks where applicable:
1 common/ types + token lib · 2 control-plane core · 3 audit store · 4 L1 ·
5 L2 (Rego + HITL) · 6 L3 sandbox · 7 L4 filter · 8 proxy orchestration ·
9 ingress adapters · 10 admin UI · 11 docker-compose + measured benchmarks.

Then three **hardening** increments (post-phase, same cadence):
- **R-12** config-bundle signing (proxy authenticates config).
- **R-2** shared Postgres nonce ledger (fleet-wide single-use).
- **R-30** opt-in real sandbox (env flag + privileged-socket overlay).

---

## 12. How to read the threat model

`THREAT_MODEL.md` has: STRIDE + OWASP-LLM mapping, a trust-boundary table, a
**controls register** (C-1…C-18, each `[IMPL]`/`[TEST]` with the phase), and a
**residual-risk register** (R-1…R-31, each with severity + plan + status). The
golden rule: **every gap is written down with a severity** — we report the real
posture, we don't claim it away. The highest-attention residuals: R-1 (gateway
bypass), R-8 (signing-key compromise), R-5/R-30 (sandbox isolation strength),
R-19 (audit is tamper-evident not -proof).

---

## 13. Testing strategy

- **Unit** (`tests/unit/`, per-layer test roots) — each layer + crypto helper in
  isolation, including config-signing round-trip/tamper.
- **Adversarial** (`tests/adversarial/`) — replay, Confused-Deputy scope misuse,
  cross-key forgery, tampering, expiry, traversal/injection payloads.
- **Integration** — control-api end-to-end (login → register → signed bundle →
  HITL mint/verify → nonce single-use → audit append/verify) via FastAPI TestClient.
- **Benchmarks** (`tests/bench/`) — decision-path p50/p95/p99 and warm-pool vs
  cold-start; numbers are pasted into the README from a real run, never fabricated.

---

## 14. Key design decisions & trade-offs

- **Native Python L2 vs WASM Rego.** Native keeps the decision path in-process and
  fast; Rego is the portable spec. They must stay in sync (R-23).
- **In-memory nonce default, shared ledger opt-in.** Correct + fast for a single
  instance; a scaled fleet must switch to the ledger (R-2) — the trade is a network
  hop on the *rare* HITL path, off the common hot path.
- **Sandbox off by default.** Real execution needs a privileged Docker socket
  (R-30); shipping it on by default would bake a host-root mount into the demo.
- **Last-known-good cached config.** Availability over immediacy: a revoked policy
  has up to one TTL to propagate (R-6) — but the proxy never "fails open".
- **Audit after execution.** A tool's side effect happens before its record commits;
  if the audit write then fails the call fails closed, but the effect already
  happened (R-28). The ephemeral sandbox bounds the blast radius.
- **One signing key, today.** Config + tokens share it (R-12 residual) — a separate,
  rotated config key is the next refinement.

---

## 15. Glossary

- **Intent** — the normalized, frozen representation of one attempted tool call.
- **PolicyProfile** — the reusable capability unit an agent inherits.
- **ConfigBundle** — a signed profile snapshot the proxy caches.
- **HITL** — Human-In-The-Loop; an action requiring human approval before it runs.
- **Decision path** — L1+L2, the in-process latency-budgeted hot path.
- **Fail-closed** — on any error/ambiguity, deny (never allow by default).
- **Security event** — a decision flagged as probable abuse (forgery, replay,
  traversal, injection), surfaced on the attack dashboards.
- **Residual risk (R-n)** — a known, documented gap with a severity and a plan.

---

*MLPEF is one deterministic enforcement layer in a defense-in-depth program. It
makes agent actions governable and auditable; it does not make them risk-free.*
