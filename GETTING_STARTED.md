# Getting Started with MLPEF — A Step-by-Step Walkthrough

This guide walks you, click by click, through the thing MLPEF is built to do:
**watch an AI agent try to act, block it, then let you safely allow it — with a
full record of what happened.** No prior MLPEF knowledge is assumed.

> **Before you begin:** you need MLPEF running and to be logged into the admin
> portal at <http://localhost:8081>. If you're not there yet, do
> **[`SETUP.md`](SETUP.md)** first — it takes about 15 minutes.

---

## The one big idea

An AI agent "thinks" (decides what it wants to do) and then "acts" (actually does
it). MLPEF sits **between** those two steps. Every action an agent wants to take is
proposed to MLPEF first, and MLPEF runs it through **five checks in order**:

| # | Layer | Plain-English question it answers |
|---|---|---|
| **L1** | Validate | Is this request even well-formed and safe-shaped? |
| **L2** | Policy | Is this agent *allowed* to do this? Or does a human need to approve it? |
| **L3** | Sandbox | Run the action inside a locked-down, throwaway container. |
| **L4** | Filter | Scan the result for secrets/PII/injection before returning it. |
| **L5** | Audit | Record the entire decision in a tamper-evident log. |

The action happens **only if every check passes**. Anything that fails is
**blocked** and logged. New agents start able to do **nothing** — you grant
capabilities deliberately.

> **Remember:** in MLPEF, *a blocked action is success, not failure.* You're about
> to see exactly that.

---

## What you'll do in this walkthrough

1. Take a quick tour of the admin portal.
2. Run a sample agent and **watch MLPEF block it**.
3. Find that block in the **audit trail** and inspect the five-layer decision.
4. **Allow** the action and see the agent succeed.
5. *(Optional)* Make the action actually execute for real.
6. *(Optional)* Require a human to approve an action.

Steps 1–4 are the core. Take them slowly; they're the whole idea.

---

## Step 1 — Take a quick tour

Logged in at <http://localhost:8081>, you'll find these sections. Just read this
list for now — you'll use them as you go:

- **Agents** — the AI agents MLPEF knows about. A demo one is already set up.
- **Policy Profiles** — reusable rule sets that say what an agent may do. This is
  where you grant or restrict capabilities.
- **Tools** — the catalog of actions agents can request (e.g. "run a shell
  command", "read a file").
- **HITL Queue** — "Human-In-The-Loop": actions that are paused waiting for a
  person to approve them.
- **Audit Explorer** — the searchable log of every decision MLPEF has made.
- **Dashboard** — at-a-glance numbers (how many actions blocked, and so on).

---

## Step 2 — Run the sample agent and watch it get blocked

MLPEF ships a tiny **sample agent** whose only job is to ask to run one shell
command: `echo "hello from a governed agent"`. Let's run it.

Open a **new terminal window** (leave the one running MLPEF alone), go to your
`MLPEF` folder, and run:

```bash
docker compose --profile demo run --rm sample-agent
```

**What you'll see:** a single line printed to the terminal, starting with `403`
and showing an outcome of **`DENY`**, along with a reason explaining that the tool
isn't permitted. Something like:

```
403  { ... "outcome": "DENY", ... reason: tool not allowed ... }
```

**Why did that happen?** The sample agent is on a **locked-down profile** — it's
allowed to do nothing by default. It asked to run `shell.exec`, that tool isn't on
its allowlist, so **Layer 2 (Policy) blocked it.** This is MLPEF working exactly as
designed: deny by default.

---

## Step 3 — See the block in the audit trail

Every decision — including that block — is recorded. Let's look at it.

1. In the portal, open **Audit Explorer**.
2. Find the most recent record — it'll be the **DENY** you just triggered for the
   sample agent and the `shell.exec` action. Click it to expand.
3. You'll see the **five-layer trace**: the record shows how the request moved
   through the layers and exactly where it was stopped (Layer 2, Policy).
4. Look for the **chain-verify** button. Click it. MLPEF re-checks the log's
   cryptographic hash-chain and confirms **no record has been altered, dropped, or
   reordered.** This is what "tamper-evident" means in practice: you can *prove*
   the log is intact.

> This audit trail is the point of MLPEF as much as the blocking is: not just
> *"we stopped it,"* but *"here is provable evidence of every decision."*

---

## Step 4 — Allow the action

Now let's *grant* the capability and watch the same agent succeed. You'll edit the
policy profile the sample agent uses.

1. Open **Policy Profiles**.
2. Open the **locked-down default profile** — the one assigned to the sample
   agent. (Not sure which one? Check the **Agents** page; the sample agent's row
   shows its profile.)
3. Find the **tool allowlist** and add the tool **`shell.exec`** to it.
4. **Save.** The UI may warn you how many agents this profile affects — for now
   it's just the sample agent, so save.

Now run the sample agent again, exactly as before:

```bash
docker compose --profile demo run --rm sample-agent
```

**What you'll see this time:** a line starting with `200` and an outcome of
**`ALLOW`** — but with **empty output**. That's expected. In this default demo
setup, MLPEF's sandbox is **turned off**, so it *approves* the action (L1, L2, and
L5 all ran and passed) but doesn't actually execute the command — Layers 3 and 4
are skipped. You just changed a **DENY** into an **ALLOW** purely by editing a
policy, with no change to the agent itself.

Go back to **Audit Explorer** and refresh: you'll now see a matching **ALLOW**
record right next to your earlier DENY. Two decisions, both logged.

**You've now seen the whole core idea: default-deny, central policy control, and a
provable record of every outcome.** Everything below is optional.

---

## Step 5 *(optional)* — Make the action really execute

Want to see the command actually run and return `hello from a governed agent`
instead of empty output? Turn on the real **sandbox**, which executes allowed
commands inside a hardened, throwaway container.

Stop MLPEF (`Ctrl + C` in the terminal running it, or `docker compose down`), then
start it with the sandbox overlay added:

```bash
docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up --build
```

Run the sample agent again. Because `shell.exec` is now allowed **and** the
sandbox is on, you'll get a `200` **ALLOW** whose output actually contains
`hello from a governed agent` — executed safely in an isolated container, with its
output scanned by Layer 4 on the way back.

> ⚠️ **Only do this on a computer you trust.** The sandbox overlay gives MLPEF
> direct access to Docker on your machine to create those containers. It's fine for
> local learning, but it is **not** how you'd run this in production — see
> [`DEPLOYMENT.md`](DEPLOYMENT.md) §8 for the safe way.

---

## Step 6 *(optional)* — Require a human to approve an action

Some actions are too sensitive to auto-allow. MLPEF can **pause** them until a
person clicks "approve." This is **HITL** (Human-In-The-Loop).

The idea, end to end:

1. A policy rule marks an action as needing approval.
2. When the agent attempts it, MLPEF returns **`HITL_REQUIRED`** (HTTP `202`) and
   does **not** run it. The request appears in the **HITL Queue**.
3. An approver opens the **HITL Queue** and approves it. MLPEF mints a **scoped,
   single-use, expiring** approval token.
4. A fully-integrated agent automatically retries **with that token**, and the
   action runs once — then the token can never be reused.

You can watch stages 2 and 3 yourself: add a HITL rule for `shell.exec` to the
profile, run the sample agent, and see the `202` result land in the **HITL
Queue**, then approve it there. The automatic retry in stage 4 is something a
*real* integrated agent does for you; the exact rule format and the full retry
loop are documented in [`DEPLOYMENT.md`](DEPLOYMENT.md) §14 and
[`AGENT_SETUP.md`](AGENT_SETUP.md).

---

## Recap

You have:

- Run an agent and watched MLPEF **block it by default**.
- Read the **tamper-evident audit trail** and cryptographically verified it.
- **Allowed** the action by editing a central policy — no agent changes.
- *(Optionally)* executed the action for real, and seen how human approval works.

That's MLPEF in a nutshell: **agents can only do what policy permits, and every
decision is provably recorded.**

---

## Where to go next

- **[`AGENT_SETUP.md`](AGENT_SETUP.md)** — connect *your own* AI agent (Claude,
  an OpenAI-style loop, a custom app) to MLPEF.
- **[`DEPLOYMENT.md`](DEPLOYMENT.md)** — configuration, policy design, human
  approval in depth, and running MLPEF for real.
- **[`ARCHITECTURE.md`](ARCHITECTURE.md)** — how the five layers work under the
  hood.
- **[`THREAT_MODEL.md`](THREAT_MODEL.md)** — exactly what MLPEF defends against,
  and — just as importantly — what it does not.
