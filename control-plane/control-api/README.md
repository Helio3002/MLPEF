# control-api (control plane)

FastAPI service for the MLPEF control plane: admin auth + RBAC, agent
registration, policy-profile and tool CRUD, and the **config-bundle** endpoint the
proxy pulls.

## Run (in your Codespace)

From the **repo root** install deps (this also installs the `common` package):

```bash
pip install -e ".[dev,control]"
```

Then, from **this directory** (`control-plane/control-api`):

```bash
# 1. Create the schema. Default DB is sqlite:///./mlpef_control.db; set
#    DATABASE_URL=postgresql+psycopg2://user:pass@host/db for Postgres.
alembic upgrade head

# 2. Seed a superadmin, the deny-most default profile, and a sample agent.
#    Set MLPEF_ADMIN_PASSWORD to avoid the insecure default.
MLPEF_ADMIN_PASSWORD=change-me python -m app.seed

# 3. Run the API.
uvicorn app.main:app --reload --port 8080

# 4. Tests (isolated in-memory SQLite; no DB setup needed).
pytest
```

> Order matters: if you use Alembic, run `alembic upgrade head` **before**
> `python -m app.seed` (the seed also calls `create_all()` for no-Alembic quick
> starts, which would otherwise collide with Alembic's table creation).

OpenAPI docs at `http://localhost:8080/docs`.

## Auth model

- **Admins** authenticate via `POST /auth/login` (username + password) and receive
  a session **bearer token**. Send it as `Authorization: Bearer <token>`.
  Passwords are PBKDF2-HMAC-SHA256; sessions are random tokens stored as SHA-256.
- **Agents/proxy** authenticate to `GET /agents/{id}/config-bundle` with their API
  key in `X-Agent-Key`. The key is shown **once** at registration and stored only
  as a SHA-256 hash.

RBAC roles: `superadmin`, `security-reviewer` (edit policy/agents/tools),
`approver` (HITL — wired in Phase 5), `read-only`. Reads require any
authenticated admin; writes require `superadmin`/`security-reviewer`; profile
delete requires `superadmin`.

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/auth/login` | — | issue session token |
| GET | `/auth/me` | admin | current admin |
| POST | `/agents` | write | register; returns API key once; default profile if none given |
| GET | `/agents` | admin | list (optional `?tenant=`) |
| GET | `/agents/{id}` | admin | detail (no credential) |
| POST | `/agents/{id}/suspend` \| `/activate` | write | lifecycle |
| POST | `/agents/{id}/profile` | write | reassign profile |
| GET | `/agents/{id}/config-bundle` | agent key | resolved profile bundle for the proxy |
| GET\|POST\|PUT\|DELETE | `/profiles[...]` | admin/write | CRUD; `GET /profiles/{id}/impact` shows affected agents |
| GET\|PUT\|DELETE | `/tools[...]` | admin/write | tool registry |

## Notes / current limitations (tracked in `THREAT_MODEL.md`)

- SQLite is the dev default; Postgres is used in compose/prod.
- HITL token minting + the audit store land in Phases 5 and 3; this service
  currently covers registration, central config, and the config-bundle pull.
- `mypy --strict` is enforced on `common/`; the service's own typing is tightened
  once it's confirmed running in CI.
