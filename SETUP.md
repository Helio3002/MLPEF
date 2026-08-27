# Setting Up MLPEF — A Beginner's Guide

This page gets MLPEF running on your computer from a completely clean start. No
prior experience with MLPEF is assumed. By the end you'll have the whole platform
running locally and be able to log into its admin portal in your browser.

Once it's running, follow **[`GETTING_STARTED.md`](GETTING_STARTED.md)** for a
guided, click-by-click tour of what MLPEF actually *does*.

> **Time needed:** about 15–20 minutes, most of it waiting for Docker to download
> and build things the first time.

---

## What is MLPEF, in one paragraph?

MLPEF is a security checkpoint for AI agents. When an AI agent tries to *do*
something — run a command, read a file, call an API — MLPEF intercepts that
request and runs it through five safety checks. The action only happens if **all
five** checks pass; otherwise it's blocked and written to a tamper-evident log.
You run MLPEF as a small set of services on your machine; you manage it from a web
page in your browser.

> **A note on expectations.** MLPEF is defense-in-depth that you can *measure* —
> not a magic shield. It can only police actions that are actually routed through
> it, and it never claims "100% protection." That honesty is built into the
> project (see [`THREAT_MODEL.md`](THREAT_MODEL.md)). For now, just know that a
> *blocked* action is MLPEF working correctly, not an error.

---

## Before you start: what you need

You need three things installed. Don't worry — we'll check each one.

### 1. A terminal

A terminal is a text window where you type commands.

- **macOS:** press `Cmd + Space`, type `Terminal`, press Enter.
- **Windows:** press the Start button, type `PowerShell`, press Enter.
- **Linux:** open your **Terminal** app.

You'll paste commands into this window and press Enter to run them.

### 2. Docker Desktop

Docker is the tool that runs MLPEF's services in neat, self-contained boxes
("containers") so you don't have to install databases and web servers by hand.

- Download and install **Docker Desktop**: <https://www.docker.com/products/docker-desktop/>
- After installing, **start Docker Desktop** and wait until its whale icon says
  it's running.

**Check it worked.** In your terminal, run:

```bash
docker compose version
```

You should see a version number like `Docker Compose version v2.x.x`. If you get
"command not found," Docker isn't installed or isn't started yet.

### 3. Git (to download the code)

Git downloads a copy of the MLPEF code to your machine.

**Check if you already have it:**

```bash
git --version
```

If you see a version number, you're set. If not, install it from
<https://git-scm.com/downloads> (or, on a Mac, running the command above will
offer to install it for you).

You'll also need **access to the MLPEF repository** on GitHub. If the project is
private, make sure your GitHub account has been granted access first.

---

## Step 1 — Download the code

In your terminal, go to a folder where you keep projects (for example your home
folder), then download MLPEF into it:

```bash
git clone https://github.com/Helio3002/MLPEF.git
cd MLPEF
```

The `git clone` line copies the project into a new `MLPEF` folder. The `cd MLPEF`
line moves you *into* that folder — **run every remaining command from here.**

> Prefer SSH and have a key set up? Use
> `git clone git@github.com:Helio3002/MLPEF.git` instead. If that phrase means
> nothing to you, ignore it and use the HTTPS line above.

---

## Step 2 — Create your configuration file

MLPEF reads its settings (passwords and the like) from a file named `.env`. The
project ships an example you copy and then edit:

```bash
cp .env.example .env
```

Now open the new `.env` file in any text editor and change the placeholder
secrets. The values that say `change-me` are the ones to update:

| Setting in `.env` | What it is | What to do |
|---|---|---|
| `POSTGRES_PASSWORD` | Database password | Change to any strong value. |
| `MLPEF_ADMIN_PASSWORD` | **Your login** to the admin portal | Change it, and remember it — you'll type it in Step 5. |
| `MLPEF_ADMIN_USERNAME` | Your admin username | `admin` is fine to keep. |
| `MLPEF_SAMPLE_AGENT_API_KEY` | A demo agent's key | Fine to leave as-is for local practice. |

Everything else can stay at its default for a local run. (The comments inside the
file explain each option if you're curious.)

> These are **demo defaults for your own machine only.** Before putting MLPEF
> anywhere other people can reach, change *every* secret — see
> [`DEPLOYMENT.md`](DEPLOYMENT.md).

---

## Step 3 — Start MLPEF

This one command builds and starts everything — the database, the control plane,
the admin web portal, and the enforcement proxy:

```bash
docker compose up --build
```

**What you'll see:** a lot of scrolling text as Docker downloads images and builds
the services. The **first** run takes a few minutes. It's done starting up when
the text slows to a trickle and you see the services reporting they're ready
(lines mentioning `control-api`, `admin-ui`, and `proxy`).

**Leave this terminal window open** — it's running MLPEF. Closing it or pressing
`Ctrl + C` stops the platform. (We'll do the rest in your browser and a second
terminal.)

---

## Step 4 — Confirm it's running

Open your web browser and go to:

> **<http://localhost:8081>**

You should see the **MLPEF admin portal** login screen.

Here's what's now running on your machine:

| What | Open in browser | You'll use it for |
|---|---|---|
| **Admin portal (UI)** | <http://localhost:8081> | Everything — this is your control panel. |
| **Control API** | <http://localhost:8080/docs> | The raw API (optional; for the curious). |
| **Enforcement proxy** | `http://localhost:8090` | Where agents send their requests (not a web page). |

---

## Step 5 — Log in

On the login page at <http://localhost:8081>, enter:

- **Username:** the `MLPEF_ADMIN_USERNAME` from your `.env` (default `admin`)
- **Password:** the `MLPEF_ADMIN_PASSWORD` you set in Step 2

You're in. **That's setup complete.**

Next, head to **[`GETTING_STARTED.md`](GETTING_STARTED.md)** to watch MLPEF block
an agent, then allow it, and read the audit trail — the whole point of the tool.

---

## Stopping, starting, and resetting

| I want to… | Do this |
|---|---|
| **Stop MLPEF** | Go to the terminal running it and press `Ctrl + C`. Or, from the `MLPEF` folder in another terminal: `docker compose down`. |
| **Start it again** | From the `MLPEF` folder: `docker compose up` (no `--build` needed after the first time). |
| **Start it in the background** | `docker compose up -d` (runs quietly; use `docker compose logs -f` to watch it, `docker compose down` to stop). |
| **Wipe everything and start fresh** | `docker compose down -v` — this **deletes the database**, including your admin login and any changes. The next start re-seeds defaults. |

---

## Running on GitHub Codespaces (optional)

If you're running MLPEF in a **GitHub Codespace** instead of your own machine, the
setup commands are identical, with one extra step so the browser can reach the UI:

1. Open the **Ports** tab in the Codespace.
2. Find port **8081**, right-click it, and set **Port Visibility → Public**.
3. Open the forwarded `…-8081.app.github.dev` URL. The first time, click GitHub's
   **Continue** button on the interstitial page. Then log in as in Step 5.

No other changes are needed — the admin portal talks to the API through its own
address, so it "just works" on a forwarded host.

---

## If something goes wrong

| Problem | Likely cause & fix |
|---|---|
| `docker: command not found` or `docker compose` errors | Docker Desktop isn't installed or isn't started. Install it, launch it, wait for the whale icon to say "running," then retry. |
| The page at `localhost:8081` won't load | Give it another minute — the first startup is slow. Check the terminal from Step 3 for errors. Confirm the services are up with `docker compose ps` (run from the `MLPEF` folder). |
| "Port is already allocated" / address in use | Another program is using port 8080, 8081, or 8090. Stop that program, or stop any old MLPEF run with `docker compose down`, then retry. |
| I can log in but nothing works / login is rejected | Make sure you're using the username and password from *your* `.env`. If you changed `MLPEF_ADMIN_PASSWORD` **after** the first start, it won't update an existing account — reset with `docker compose down -v` then `docker compose up` (this wipes data). |
| Everything is broken and I just want a clean slate | From the `MLPEF` folder: `docker compose down -v` then `docker compose up --build`. |

Still stuck? The deeper, operator-focused reference is
[`DEPLOYMENT.md`](DEPLOYMENT.md) (see its "Operations runbook" section).

---

## Where to go next

- **[`GETTING_STARTED.md`](GETTING_STARTED.md)** — the guided, step-by-step tour:
  block an agent, allow it, and read the audit trail.
- **[`README.md`](README.md)** — the big-picture overview of what MLPEF is.
- **[`AGENT_SETUP.md`](AGENT_SETUP.md)** — connect your own AI agent to MLPEF.
- **[`DEPLOYMENT.md`](DEPLOYMENT.md)** — configuration, hardening, and production.
