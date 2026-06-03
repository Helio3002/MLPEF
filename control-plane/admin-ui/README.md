# admin-ui (control plane)

React + Vite + TypeScript + Tailwind admin portal. Talks **only** to the
control-api. Every page requires login and is RBAC-gated.

## Run (in your Codespace)

```bash
cd control-plane/admin-ui
npm install
cp .env.example .env.local          # set VITE_API_BASE_URL to your control-api
npm run dev                         # http://localhost:5173
```

Other scripts: `npm run build` (type-check + production build), `npm run typecheck`.

The control-api must allow the UI origin via CORS — set `MLPEF_CORS_ORIGINS`
(comma-separated); the default already includes `http://localhost:5173`.

## Authentication + RBAC

- Log in with an admin user. The seed creates `admin` / `admin` — **change the
  password** (`MLPEF_ADMIN_PASSWORD`) for anything real.
- Login calls `POST /auth/login` and stores the returned session **bearer token**;
  every request sends `Authorization: Bearer <token>`. A `401` (expired/invalid)
  logs you out. (Token storage is browser `localStorage` — see THREAT_MODEL.md
  R-11 for the residual.)
- Role gates:
  - `read-only` — view all pages.
  - `security-reviewer` / `superadmin` — edit agents, profiles, tools.
  - `approver` / `superadmin` — approve/deny in the HITL queue.

## Pages

- **Agents** — register (API key shown once), suspend/activate, reassign profile.
- **Policy Profiles** — JSON editor CRUD; shows the affected-agent count before save.
- **Tools** — tool/schema registry + allowlist.
- **HITL Queue** — approve (mints a scoped, single-use, expiring token) or deny.
- **Audit Explorer** — filter by agent/action/outcome; expand a record's five-layer
  trace; one-click chain-integrity verification; export CSV/JSON.
- **Dashboard** — denial rate, blocked-attack counts, decision-path p50/p99.

UI copy never claims total protection — MLPEF is measurable defense-in-depth.
