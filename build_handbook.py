#!/usr/bin/env python3
"""Generate MLPEF_Handbook.pdf — a beginner-friendly guide + demo handbook.

Run with the throwaway venv that has reportlab:
    /tmp/mlpef_pdf_venv/bin/python build_handbook.py
"""

from __future__ import annotations

import datetime
import pathlib

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

OUT = pathlib.Path(__file__).resolve().parent / "MLPEF_Handbook.pdf"

# --------------------------------------------------------------------------- #
# Styles
# --------------------------------------------------------------------------- #
ss = getSampleStyleSheet()
NAVY = colors.HexColor("#1f2d50")
BLUE = colors.HexColor("#2563eb")
GREEN = colors.HexColor("#15803d")
AMBER = colors.HexColor("#b45309")
GREYBG = colors.HexColor("#f3f4f6")
CODEBG = colors.HexColor("#0f172a")

styles = {
    "title": ParagraphStyle("title", parent=ss["Title"], fontSize=30, leading=34,
                            textColor=NAVY, spaceAfter=6),
    "subtitle": ParagraphStyle("subtitle", parent=ss["Normal"], fontSize=14, leading=18,
                               textColor=BLUE, alignment=TA_CENTER, spaceAfter=4),
    "tag": ParagraphStyle("tag", parent=ss["Normal"], fontSize=11, leading=16,
                          textColor=colors.HexColor("#475569"), alignment=TA_CENTER),
    "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontSize=19, leading=23, textColor=NAVY,
                         spaceBefore=14, spaceAfter=8),
    "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontSize=14, leading=18, textColor=BLUE,
                         spaceBefore=10, spaceAfter=5),
    "h3": ParagraphStyle("h3", parent=ss["Heading3"], fontSize=11.5, leading=15,
                         textColor=colors.HexColor("#0f172a"), spaceBefore=7, spaceAfter=3),
    "body": ParagraphStyle("body", parent=ss["Normal"], fontSize=10, leading=14.5,
                           alignment=TA_LEFT, spaceAfter=6),
    "bullet": ParagraphStyle("bullet", parent=ss["Normal"], fontSize=10, leading=14),
    "code": ParagraphStyle("code", parent=ss["Code"], fontName="Courier", fontSize=8,
                           leading=10.5, textColor=colors.whitesmoke, backColor=CODEBG,
                           borderPadding=6, leftIndent=2, spaceBefore=3, spaceAfter=8),
    "cell": ParagraphStyle("cell", parent=ss["Normal"], fontSize=9, leading=12),
    "cellh": ParagraphStyle("cellh", parent=ss["Normal"], fontSize=9, leading=12,
                            textColor=colors.white, fontName="Helvetica-Bold"),
}


def callout_style(color: colors.Color, bg: colors.Color) -> ParagraphStyle:
    return ParagraphStyle("c", parent=styles["body"], textColor=colors.HexColor("#0f172a"),
                          backColor=bg, borderColor=color, borderWidth=0.6, borderPadding=7,
                          leftIndent=2, rightIndent=2, spaceBefore=4, spaceAfter=8, leading=14)


SAY_BG = colors.HexColor("#ecfdf5")
TIP_BG = colors.HexColor("#eff6ff")
WARN_BG = colors.HexColor("#fffbeb")

story: list = []


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def H1(t: str) -> None:
    story.append(Paragraph(t, styles["h1"]))


def H2(t: str) -> None:
    story.append(Paragraph(t, styles["h2"]))


def H3(t: str) -> None:
    story.append(Paragraph(t, styles["h3"]))


def P(t: str) -> None:
    story.append(Paragraph(t, styles["body"]))


def CODE(t: str) -> None:
    # Preformatted renders text verbatim (no markup/entity parsing), so pass raw.
    story.append(Preformatted(t.strip("\n"), styles["code"]))


def BULLETS(items: list[str]) -> None:
    li = [ListItem(Paragraph(x, styles["bullet"]), leftIndent=14, value="•") for x in items]
    story.append(ListFlowable(li, bulletType="bullet", start="•", leftIndent=12, spaceAfter=6))


def SAY(t: str) -> None:
    story.append(Paragraph("<b>SAY THIS:</b> " + t, callout_style(GREEN, SAY_BG)))


def TIP(t: str) -> None:
    story.append(Paragraph("<b>TIP:</b> " + t, callout_style(BLUE, TIP_BG)))


def WARN(t: str) -> None:
    story.append(Paragraph("<b>WATCH OUT:</b> " + t, callout_style(AMBER, WARN_BG)))


def SP(h: float = 6) -> None:
    story.append(Spacer(1, h))


def HR() -> None:
    story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#cbd5e1"),
                            spaceBefore=6, spaceAfter=8))


def PB() -> None:
    story.append(PageBreak())


def TABLE(rows: list[list[str]], widths: list[float], header: bool = True) -> None:
    data = []
    for r, row in enumerate(rows):
        st = styles["cellh"] if (header and r == 0) else styles["cell"]
        data.append([Paragraph(c, st) for c in row])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, GREYBG]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    t.setStyle(TableStyle(style))
    story.append(t)
    SP(8)


# =========================================================================== #
# COVER
# =========================================================================== #
SP(90)
story.append(Paragraph("MLPEF", styles["title"]))
story.append(Paragraph("Multi-Layer Policy Enforcement Framework", styles["subtitle"]))
SP(10)
story.append(Paragraph("The Complete Guide &amp; Demo Handbook", styles["subtitle"]))
SP(16)
story.append(Paragraph(
    "Understand it. Run it. Demo it on real agents.<br/>"
    "Written so a beginner can learn every part — and teach it to others.", styles["tag"]))
SP(24)
story.append(HRFlowable(width="60%", thickness=1, color=BLUE, hAlign="CENTER"))
SP(14)
story.append(Paragraph(
    "A deterministic Zero-Trust security layer that decides what autonomous "
    "AI agents are allowed to DO.", styles["tag"]))
SP(40)
story.append(Paragraph(
    f"Generated {datetime.date.today().isoformat()} &nbsp;|&nbsp; covers the full "
    "control plane, data-plane proxy, five enforcement layers, and live demos.",
    styles["tag"]))
PB()

# =========================================================================== #
# CONTENTS
# =========================================================================== #
H1("What is in this handbook")
TABLE([
    ["Part", "You will learn"],
    ["1. The Big Picture", "What MLPEF is, the problem it solves, the core idea — in plain English."],
    ["2. How It Is Built", "The two halves, the four services, the five layers, the journey of one call."],
    ["3. Setup", "Every command to get the whole system running, step by step."],
    ["4. The Admin Website", "What every page/button does."],
    ["5. Demo #1", "A one-command self-test that proves everything works."],
    ["6. Demo #2", "A live, click-by-click demo you can present to an audience."],
    ["7. Demo #3", "Connecting a REAL agent (MCP / REST / OpenAI) with exact configs."],
    ["8. Troubleshooting", "Every error you might hit and the exact fix."],
    ["9. Presenting", "A talk-track so you can explain it confidently to others."],
    ["10. Honest Limits", "What MLPEF does NOT promise (this matters)."],
    ["Appendix", "A one-page command cheat-sheet."],
], [1.7 * inch, 4.6 * inch])
PB()

# =========================================================================== #
# PART 1
# =========================================================================== #
H1("Part 1 — The Big Picture (start here)")

H2("1.1  The problem, in one breath")
P("Modern AI agents do not just chat — they <b>take actions</b>: read files, run "
  "commands, call websites and APIs, move money. That is useful, but the agent's "
  "'brain' (the language model) can be <b>tricked</b> — a malicious web page or "
  "document can say <i>'ignore your rules and delete everything'</i> — or it can "
  "simply make a mistake. If the agent can run tools directly, one bad decision "
  "becomes a real, possibly irreversible action.")

H2("1.2  What MLPEF is, in one sentence")
P("<b>MLPEF is a guard that sits in front of every tool an AI agent tries to use, "
  "and decides — with plain, predictable code that you control — whether to allow "
  "it, block it, or pause it for a human.</b> The agent proposes; MLPEF disposes.")

H2("1.3  The golden rule: 'Assume the AI is already hijacked'")
P("MLPEF never trusts the model's promises or judgement. Every guarantee comes "
  "from boring, deterministic code. The model's output is the <b>thing being "
  "checked</b>, never the thing making the decision. This is called the "
  "<b>'Assume Breach'</b> security posture.")
TIP("If you remember only one idea from this whole handbook, remember this one. "
    "Everything else is a consequence of it.")

H2("1.4  The airport-security analogy")
P("Think of MLPEF as airport security, and the AI agent as a traveller who might "
  "be carrying something dangerous without realising it. Every passenger goes "
  "through the same checkpoint, which:")
BULLETS([
    "<b>Checks the boarding pass is real and well-formed</b> (Layer 1 — Validate).",
    "<b>Checks the rulebook</b>: is this passenger allowed on this flight? (Layer 2 — Policy).",
    "<b>Opens anything risky inside a sealed, blast-proof room</b> (Layer 3 — Sandbox).",
    "<b>Screens what comes back out</b> so nothing dangerous is smuggled through (Layer 4 — Filter).",
    "<b>Writes every passenger and decision into a tamper-proof logbook</b> (Layer 5 — Audit).",
])
P("Some actions (like carrying a special item) need a <b>supervisor's signature</b> "
  "first — that is the 'human-in-the-loop' step. And the default answer to anything "
  "unclear is always <b>'No.'</b>")

H2("1.5  The three possible answers")
TABLE([
    ["Answer", "What it means"],
    ["ALLOW", "The action passed every check. It runs (or the agent runs it)."],
    ["DENY", "A check failed. The action does NOT run. It is logged with a reason."],
    ["HITL_REQUIRED", "A human must approve first. The action is paused, not run."],
], [1.8 * inch, 4.5 * inch])

H2("1.6  'Fail-closed' — the safety default")
P("If <i>anything</i> goes wrong — an error, a timeout, an unknown situation, even "
  "the logbook failing to write — MLPEF's answer is <b>DENY</b>. It never 'fails "
  "open' (never lets something through because it was confused). Safe-by-default.")

H2("1.7  The honest promise")
P("MLPEF is <b>measurable, layered defence — not a magic 100% guarantee.</b> It "
  "can only guard actions that actually pass through it, and every known weakness "
  "is written down with a severity in a file called THREAT_MODEL.md. This honesty "
  "is a feature: real security never claims to be unbreakable.")
PB()

# =========================================================================== #
# PART 2
# =========================================================================== #
H1("Part 2 — How It Is Built (the logic, inside out)")

H2("2.1  The two halves")
P("MLPEF is split into two cooperating halves so the guard stays fast and keeps "
  "working even if the admin side is down.")
TABLE([
    ["Half", "What it is", "Analogy"],
    ["Control plane", "An admin website + an API + a database. Where YOU set the "
     "rules and watch what happens.", "The security office: rulebook, badge "
     "printer, camera feeds."],
    ["Data plane", "The 'proxy' — the actual gate every tool call flows through.",
     "The checkpoint at the gate."],
], [1.2 * inch, 3.3 * inch, 1.8 * inch])

H2("2.2  The four moving parts (what runs)")
P("When you start MLPEF, four programs run together:")
TABLE([
    ["Service", "Job", "Port"],
    ["postgres", "The database — stores agents, rules, the audit logbook.", "5432"],
    ["control-api", "The brain of the office — login, rules, approvals, signing.", "8080"],
    ["admin-ui", "The website you log into.", "8081"],
    ["proxy", "The checkpoint your agents talk to.", "8090"],
], [1.3 * inch, 4.0 * inch, 0.9 * inch])
P("Important trust detail: the proxy holds only a <b>public key</b>. It can "
  "<i>verify</i> approvals and signed rules, but it can never <i>forge</i> them — "
  "so even a fully hacked proxy cannot grant itself new powers.")

H2("2.3  The five layers (the heart of MLPEF)")
P("Every tool call runs this gauntlet <b>in order</b> and stops at the <b>first</b> "
  "failure. Think of them as five gates in a row.")
TABLE([
    ["Layer", "Name", "What it checks", "Example block"],
    ["L1", "Validate", "Is the request well-formed and safe on the surface?",
     "A file path that escapes its allowed folder."],
    ["L2", "Policy", "Is this agent ALLOWED to do this? (Default = No.)",
     "A tool that is not on the agent's allowlist."],
    ["L3", "Sandbox", "If it runs code, do it in a throwaway locked-down container.",
     "Code that tries to use the network or too much memory."],
    ["L4", "Filter", "Screen the OUTPUT — redact secrets, neutralise hidden tricks.",
     "A tool result that leaks an API key."],
    ["L5", "Audit", "Write a tamper-proof record. (Unskippable.)",
     "(Never blocks; if it can't write, the whole call fails closed.)"],
], [0.5 * inch, 0.9 * inch, 2.7 * inch, 2.2 * inch])

H3("Layer 1 — Validate (fast, no-risk surface checks)")
BULLETS([
    "<b>Allowlist first:</b> an unknown tool or an unexpected argument is rejected immediately.",
    "<b>Path jailing:</b> file paths must stay inside an allowed folder (e.g. /work); '..' tricks are blocked.",
    "<b>Commands are argv lists, never shell strings:</b> so 'rm; curl evil.com' can't be smuggled in.",
    "It does NOT touch the disk or network — that keeps it on the fast 'decision path' (under ~10 ms).",
])
H3("Layer 2 — Policy (the default-deny rulebook)")
BULLETS([
    "Looks up the agent's <b>policy profile</b> (its rulebook) and answers ALLOW / DENY / NEEDS-APPROVAL.",
    "<b>Default-deny:</b> if nothing explicitly allows the action, the answer is No.",
    "If the rulebook says an action needs human approval, this is where the HITL gate triggers.",
])
H3("Layer 3 — Sandbox (only for code-running tools)")
BULLETS([
    "Runs the tool inside a fresh, throwaway container: read-only disk, no network, capped CPU/memory, no admin powers.",
    "Used once, then destroyed — so a bad action can't linger or spread.",
    "Off by default in the demo (turning it on needs Docker access — covered later).",
])
H3("Layer 4 — Filter (screen what comes back)")
BULLETS([
    "Scans the tool's OUTPUT for secrets / personal data and redacts them.",
    "<b>Neutralises injection:</b> output is treated as data, never as new instructions to the agent.",
])
H3("Layer 5 — Audit (the tamper-proof logbook)")
BULLETS([
    "Records who did what, to what, the decision, the reason, and the full five-layer trace.",
    "Each record is cryptographically chained to the previous one (like blockchain): change/remove/reorder any record and the chain breaks.",
    "<b>Unskippable:</b> if the log write fails, the whole action fails closed — no silent, unlogged actions.",
])

H2("2.4  The journey of ONE tool call")
P("Say an agent wants to read the file /work/notes.txt. Here is exactly what happens:")
BULLETS([
    "<b>1.</b> The agent sends the request to the proxy, showing its <b>ID + API key</b>.",
    "<b>2.</b> The proxy looks up who the agent is and pulls its rulebook (a <b>signed</b> config bundle), checking the signature so a faker can't slip in a permissive one.",
    "<b>3.</b> <b>L1</b>: '/work/notes.txt' stays inside /work -&gt; pass.",
    "<b>4.</b> <b>L2</b>: 'fs.read' is on the allowlist and needs no approval -&gt; pass.",
    "<b>5.</b> L3/L4 skipped (reading a file is not running code).",
    "<b>6.</b> <b>L5</b>: writes 'agent X read /work/notes.txt -&gt; ALLOW' to the chained log.",
    "<b>7.</b> Result: <b>ALLOW</b> -&gt; the read happens.",
])
P("If the same agent tried 'fs.delete' and it was not on its allowlist, L2 returns "
  "<b>DENY</b>, nothing happens, and the denial is logged. <b>A denial is the "
  "system working correctly — not an error.</b>")

H2("2.5  Human-in-the-Loop (HITL), step by step")
BULLETS([
    "<b>1.</b> Agent tries a risky action (e.g. fs.write). The rulebook says 'needs approval'.",
    "<b>2.</b> Proxy answers <b>HITL_REQUIRED</b> — the action does NOT run.",
    "<b>3.</b> A human opens the <b>HITL Queue</b> in the website and clicks <b>Approve</b>.",
    "<b>4.</b> The control plane mints a <b>one-time, time-limited, scope-locked token</b>.",
    "<b>5.</b> The agent retries the SAME action with that token -&gt; it runs, exactly once.",
    "<b>6.</b> If the agent tries to reuse the token -&gt; <b>DENY (replay)</b>.",
])

H2("2.6  The cryptography, in plain words")
TABLE([
    ["Mechanism", "What it does (plain English)"],
    ["HITL approval token", "A digital 'signed permission slip' that only the "
     "control plane can create, is locked to one exact action, expires fast, and "
     "works only once. The proxy can check it but never forge it."],
    ["Signed config bundle", "The agent's rulebook is digitally signed, so the "
     "proxy knows the rules genuinely came from the control plane and weren't "
     "swapped by an attacker on the network."],
    ["Audit hash-chain", "Each log record carries a fingerprint of the one before "
     "it. Tampering with any record breaks the chain — so the logbook is "
     "tamper-evident."],
], [1.7 * inch, 4.6 * inch])

H2("2.7  Mini-glossary")
TABLE([
    ["Term", "Meaning"],
    ["Agent", "An AI program that takes actions through tools."],
    ["Tool", "An action an agent can request: fs.read, http.get, shell.exec, ..."],
    ["Policy profile", "A reusable rulebook: which tools, which folders, what needs approval."],
    ["Proxy", "The checkpoint service that runs the five layers."],
    ["HITL", "Human-In-The-Loop — an action that needs a person to approve it."],
    ["Fail-closed", "When unsure, deny. Never allow by accident."],
    ["Residual risk", "A known, written-down weakness with a severity (in THREAT_MODEL.md)."],
], [1.7 * inch, 4.6 * inch])
PB()

# =========================================================================== #
# PART 3 — SETUP
# =========================================================================== #
H1("Part 3 — Setup (every command, step by step)")

H2("3.1  What you need")
BULLETS([
    "<b>Docker</b> and <b>Docker Compose v2</b> installed. Check with: <font face='Courier'>docker compose version</font>",
    "The MLPEF project folder (the repository).",
    "A terminal open inside that folder.",
])

H2("3.2  Step 1 — create your settings file")
P("MLPEF reads secrets and settings from a file called <b>.env</b>. Copy the "
  "example and (for real use) change the passwords:")
CODE("cp .env.example .env")
P("Open .env in any editor. The two you care about first:")
BULLETS([
    "<font face='Courier'>MLPEF_ADMIN_PASSWORD</font> — your login password for the website.",
    "<font face='Courier'>MLPEF_SAMPLE_AGENT_API_KEY</font> — the demo agent's key (fine to leave for testing).",
])

H2("3.3  Step 2 — start everything")
P("This one command builds and launches all four services:")
CODE("docker compose up --build")
P("What happens, in order:")
BULLETS([
    "<b>postgres</b> starts and becomes healthy (the database).",
    "<b>control-api</b> waits for the database, runs migrations (creates tables), then 'seeds' a first admin user, a deny-everything default rulebook, and a demo agent.",
    "<b>admin-ui</b> builds the website and serves it.",
    "<b>proxy</b> fetches the control plane's public key and is ready to guard calls.",
])
TIP("Add <font face='Courier'>-d</font> (i.e. <font face='Courier'>docker compose "
    "up --build -d</font>) to run it in the background and get your terminal back.")

H2("3.4  Step 3 — confirm it is running")
CODE("docker compose ps\ncurl http://localhost:8080/healthz")
P("You want every service 'Up' (control-api 'healthy'), and the curl should print "
  "<font face='Courier'>{\"status\":\"ok\"}</font>.")

H2("3.5  Step 4 — open the website and log in")
BULLETS([
    "Open <b>http://localhost:8081</b> in your browser.",
    "Log in with username <b>admin</b> and the password from your .env "
    "(the default is <b>admin</b>).",
])

H2("3.6  If you are on GitHub Codespaces (remote)")
P("The website talks to the API through its own address, so you only need to "
  "expose ONE port:")
BULLETS([
    "In the <b>Ports</b> tab, set port <b>8081</b> visibility to <b>Public</b>.",
    "Open the forwarded '...-8081...' URL and click GitHub's <b>Continue</b> once.",
    "That is it — no other config, because the website proxies the API under /api.",
])
WARN("If login shows 'connection refused' or a CORS error, it is almost always the "
     "port-visibility / forwarded-URL issue above — not a bug in MLPEF.")
PB()

# =========================================================================== #
# PART 4 — UI TOUR
# =========================================================================== #
H1("Part 4 — The Admin Website, page by page")
P("Your login has a <b>role</b> that decides what you can change. The seeded "
  "'admin' is a <b>superadmin</b> and can do everything.")
TABLE([
    ["Page", "What it is for", "What you do there"],
    ["Dashboard", "A glance at health.", "See denial rate, blocked-attack counts, "
     "and decision speed (p50/p99)."],
    ["Agents", "Manage who can connect.", "Register an agent (get its API key, "
     "shown ONCE), suspend/activate, reassign its rulebook."],
    ["Policy Profiles", "The rulebooks.", "Create/edit a profile (a JSON editor): "
     "allowed tools, folders, what needs approval. Shows how many agents an edit "
     "affects."],
    ["Tools", "Catalogue of known tools.", "Register a tool name + its argument shape."],
    ["HITL Queue", "Human approvals.", "Approve (mints a one-time token) or deny "
     "pending requests."],
    ["Audit Explorer", "The tamper-proof logbook.", "Filter records, expand the "
     "five-layer trace, click 'verify chain', export CSV/JSON."],
], [1.2 * inch, 2.0 * inch, 3.1 * inch])
PB()

# =========================================================================== #
# PART 5 — DEMO 1
# =========================================================================== #
H1("Part 5 — Demo #1: the one-command self-test")
P("This is the easiest way to prove the entire system works. It is a script that "
  "plays both an agent and an admin, runs 11 checks, and prints PASS/FAIL.")

H2("5.1  Run it")
CODE("python data-plane/ingress/examples/test_agent.py --admin-pass \"admin\"")
P("Run it from the project root, on the same machine as the stack (in Codespaces, "
  "run it inside the Codespace — not the browser).")

H2("5.2  What the 11 checks prove")
TABLE([
    ["Check", "Proves"],
    ["ALLOW fs.read / shell.exec echo", "Permitted actions pass (L1 + L2)."],
    ["DENY fs.delete", "Default-deny: tools not on the allowlist are blocked."],
    ["BLOCK path traversal", "L1 stops an attempt to read outside the allowed folder."],
    ["BLOCK command injection", "L1 stops a dangerous command (rm -rf /)."],
    ["GATE fs.write", "L2 pauses a risky action for human approval."],
    ["APPROVE + retry", "The control plane mints a token and the proxy accepts it once."],
    ["BLOCK replay", "Re-using the one-time token is rejected."],
    ["SIGNED bundle", "The agent's rulebook is digitally signed (config integrity)."],
    ["CHAIN verifies", "The audit logbook is intact and tamper-evident (L5)."],
], [2.4 * inch, 3.9 * inch])

H2("5.3  What success looks like")
CODE("RESULT: 11/11 checks passed.\nAll checks passed - MLPEF is enforcing end to end.")
SAY("'This single command just exercised all five layers, the human-approval flow, "
    "the one-time-token replay protection, the signed rulebook, and the "
    "tamper-proof audit log. Eleven out of eleven — the platform is enforcing end "
    "to end.'")
PB()

# =========================================================================== #
# PART 6 — DEMO 2 (LIVE MANUAL)
# =========================================================================== #
H1("Part 6 — Demo #2: the live manual demo (the showstopper)")
P("This is the demo to present to an audience. You will create an agent, give it a "
  "rulebook, then watch MLPEF allow safe actions, block attacks, and pause a risky "
  "one for your approval — all visible in the website. Every click and command is "
  "below.")

H2("6.0  Pre-flight (do this before the audience arrives)")
BULLETS([
    "Make sure the stack is up: <font face='Courier'>docker compose ps</font>.",
    "Log into the website (http://localhost:8081) in one browser tab.",
    "Have a terminal open in the project folder in another window.",
])

H2("6.1  Register an agent (website)")
BULLETS([
    "Go to <b>Agents</b> -&gt; click <b>Register</b>.",
    "Name it <b>demo-bot</b> -&gt; submit.",
    "<b>Copy two things now:</b> the <b>Agent ID</b> (long hex string) and the "
    "<b>API key</b> (starts with mlpef_). The key is shown only once.",
])
WARN("Use the Agent ID (the hex string), NOT the name 'demo-bot', in the commands "
     "later. The name is just a label.")

H2("6.2  Create a rulebook (website)")
P("Go to <b>Policy Profiles</b> -&gt; <b>New</b> -&gt; paste this exactly, then <b>Save</b>:")
CODE('{\n'
     '  "profile_id": "demo-policy",\n'
     '  "name": "Demo policy",\n'
     '  "tenant": "default",\n'
     '  "tool_allowlist": ["fs.read", "shell.exec", "fs.write"],\n'
     '  "resource_scopes": [{ "kind": "path", "jail_prefix": "/work" }],\n'
     '  "hitl_rules": [{ "action_pattern": "fs.write", "resource_pattern": "*" }]\n'
     '}')
P("In plain words: this agent may read files and run a few safe commands inside the "
  "/work folder, and any file WRITE must be approved by a human.")

H2("6.3  Assign the rulebook (website)")
BULLETS([
    "Go to <b>Agents</b> -&gt; open <b>demo-bot</b> -&gt; reassign profile -&gt; <b>demo-policy</b>.",
])

H2("6.4  Point the proxy's audit identity at this agent (terminal)")
P("So this agent's actions are logged cleanly, set its key as the proxy's audit "
  "identity, then restart the proxy:")
CODE("# in .env, add this line (use demo-bot's real key):\n"
     "MLPEF_PROXY_AGENT_KEY=mlpef_<demo-bot-key>\n\n"
     "# then restart the proxy so it picks up the new identity:\n"
     "docker compose up -d")
TIP("Shortcut for a quick demo: instead of 6.1–6.4 you can reuse the built-in "
    "'sample-agent-demo' (its key is MLPEF_SAMPLE_AGENT_API_KEY in .env) and just "
    "give it the demo-policy in step 6.3. Then no restart is needed.")

H2("6.5  Show an ALLOWED action (terminal)")
P("Wait ~5 seconds after assigning so the proxy refreshes its rulebook cache, then:")
CODE("curl -X POST http://localhost:8090/v1/execute \\\n"
     "  -H \"X-Agent-Id: <AGENT_ID>\" -H \"X-Agent-Key: mlpef_<demo-bot-key>\" \\\n"
     "  -H 'Content-Type: application/json' \\\n"
     "  -d '{\"tool\":\"fs.read\",\"action\":\"fs.read\",\n"
     "       \"resource\":\"/work/notes.txt\",\n"
     "       \"arguments\":{\"path\":\"/work/notes.txt\"}}'")
P("Expected: a response containing <font face='Courier'>\"verdict\":\"allow\"</font>.")
SAY("'This file read is inside the allowed folder and on the allowlist, so MLPEF "
    "lets it through.'")

H2("6.6  Show a DEFAULT-DENY (terminal)")
P("Try a tool the rulebook never allowed:")
CODE("curl -X POST http://localhost:8090/v1/execute \\\n"
     "  -H \"X-Agent-Id: <AGENT_ID>\" -H \"X-Agent-Key: mlpef_<demo-bot-key>\" \\\n"
     "  -H 'Content-Type: application/json' \\\n"
     "  -d '{\"tool\":\"fs.delete\",\"action\":\"fs.delete\",\n"
     "       \"resource\":\"/work/x\",\"arguments\":{\"path\":\"/work/x\"}}'")
P("Expected: <font face='Courier'>\"verdict\":\"deny\"</font>, "
  "<font face='Courier'>\"reason_code\":\"unknown_tool\"</font>.")
SAY("'We never granted delete, so the default answer is No. That is default-deny: "
    "nothing is allowed unless we explicitly permit it.'")

H2("6.7  Show an ATTACK being blocked — path traversal (terminal)")
CODE("curl -X POST http://localhost:8090/v1/execute \\\n"
     "  -H \"X-Agent-Id: <AGENT_ID>\" -H \"X-Agent-Key: mlpef_<demo-bot-key>\" \\\n"
     "  -H 'Content-Type: application/json' \\\n"
     "  -d '{\"tool\":\"fs.read\",\"action\":\"fs.read\",\n"
     "       \"resource\":\"/etc/passwd\",\"arguments\":{\"path\":\"/etc/passwd\"}}'")
P("Expected: <font face='Courier'>\"verdict\":\"deny\"</font>, "
  "<font face='Courier'>\"reason_code\":\"path_traversal\"</font>, "
  "<font face='Courier'>\"security_event\":true</font>.")
SAY("'The agent tried to escape its /work folder and read a system password file. "
    "Layer 1 caught it and flagged it as a security event — this is a real attack "
    "pattern being stopped.'")

H2("6.8  Show an ATTACK being blocked — command injection (terminal)")
CODE("curl -X POST http://localhost:8090/v1/execute \\\n"
     "  -H \"X-Agent-Id: <AGENT_ID>\" -H \"X-Agent-Key: mlpef_<demo-bot-key>\" \\\n"
     "  -H 'Content-Type: application/json' \\\n"
     "  -d '{\"tool\":\"shell.exec\",\"action\":\"shell.exec\",\n"
     "       \"resource\":\"-\",\"arguments\":{\"argv\":[\"rm\",\"-rf\",\"/\"]}}'")
P("Expected: <font face='Courier'>\"verdict\":\"deny\"</font>, "
  "<font face='Courier'>\"reason_code\":\"command_injection\"</font>.")
SAY("'It tried to run a destructive command. Only a tiny allowlist of safe programs "
    "is permitted, so this is blocked before it can ever run.'")

H2("6.9  Show Human-in-the-Loop (terminal + website)")
H3("(a) The agent tries a risky write — it gets paused")
CODE("curl -X POST http://localhost:8090/v1/execute \\\n"
     "  -H \"X-Agent-Id: <AGENT_ID>\" -H \"X-Agent-Key: mlpef_<demo-bot-key>\" \\\n"
     "  -H 'Content-Type: application/json' \\\n"
     "  -d '{\"tool\":\"fs.write\",\"action\":\"fs.write\",\n"
     "       \"resource\":\"/work/report.txt\",\n"
     "       \"arguments\":{\"path\":\"/work/report.txt\",\"content\":\"hello\"}}'")
P("Expected: <font face='Courier'>\"verdict\":\"hitl_required\"</font>. The write "
  "did NOT happen.")
H3("(b) Open a request, then approve it")
P("The agent now asks for approval (this is what a real integration does "
  "automatically). Create the request, then approve in the website:")
CODE("# get an admin token\n"
     "TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \\\n"
     "  -H 'Content-Type: application/json' \\\n"
     "  -d '{\"username\":\"admin\",\"password\":\"admin\"}' | python3 -c \\\n"
     "  'import sys,json;print(json.load(sys.stdin)[\"token\"])')\n\n"
     "# the agent opens an approval request\n"
     "curl -s -X POST http://localhost:8080/hitl/requests \\\n"
     "  -H \"X-Agent-Key: mlpef_<demo-bot-key>\" -H 'Content-Type: application/json' \\\n"
     "  -d '{\"action\":\"fs.write\",\"resource\":\"/work/report.txt\"}'")
BULLETS([
    "In the website, open <b>HITL Queue</b> -&gt; you will see the pending request.",
    "Click <b>Approve</b>. A one-time token is created.",
])
SAY("'A human is now in the loop. Nothing destructive happens automatically — a "
    "person must explicitly approve it, and they can see exactly what is being "
    "requested.'")
H3("(c) Retry WITH the token — it works once")
P("Copy the token the UI shows (or the approve API returns) and retry the write "
  "with an extra field <font face='Courier'>\"approval_token\":\"...\"</font>. It "
  "now returns <font face='Courier'>\"verdict\":\"allow\"</font>.")
H3("(d) Replay the SAME token — it is rejected")
P("Run the exact same approved request again. Expected: "
  "<font face='Courier'>\"verdict\":\"deny\"</font>, "
  "<font face='Courier'>\"reason_code\":\"token_replay\"</font>.")
SAY("'The permission slip is one-time-use. Even if an attacker steals it, they "
    "cannot reuse it.'")

H2("6.10  Show the tamper-proof logbook (website)")
BULLETS([
    "Open <b>Audit Explorer</b>. Every action you just did is listed.",
    "Click a row to <b>expand its five-layer trace</b> — see exactly which layer decided and why.",
    "Click <b>verify chain</b> -&gt; it confirms the whole logbook is intact.",
])
SAY("'Every decision is recorded in a chained, tamper-evident log. One click proves "
    "nothing has been altered, removed, or reordered.'")

H2("6.11  Show the Dashboard (website)")
BULLETS([
    "Open <b>Dashboard</b>: the denial rate and the blocked-attack count went up "
    "from your demo, and you can see how fast decisions are (p50/p99).",
])

H2("6.12  Reset (optional)")
P("To put things back: Agents -&gt; demo-bot -&gt; reassign to "
  "<b>default-locked-down</b> (deny everything again).")
PB()

# =========================================================================== #
# PART 7 — DEMO 3 (REAL AGENT)
# =========================================================================== #
H1("Part 7 — Demo #3: govern a REAL agent")
P("Demos #1 and #2 use curl as the 'agent'. Now connect a real AI agent. The rule "
  "is always the same: <b>make the agent's tool calls flow through the proxy</b>, "
  "and only act on ALLOW. Pick the path that matches your agent.")

H2("7.1  The non-negotiable rule")
WARN("MLPEF only guards calls that go THROUGH it. The agent must not be able to "
     "reach its tools any other way. Enforce this with network rules so the proxy "
     "is the only path out.")

H2("7.2  Path A — MCP agents (no code; recommended)")
P("If your agent speaks MCP (Model Context Protocol) — e.g. Claude Desktop, Cline, "
  "Cursor, or LangGraph via langchain-mcp-adapters — MLPEF ships a ready-made MCP "
  "gateway. You only configure it.")
H3("Step 1 — set the agent identity in .env")
CODE("MLPEF_MCP_AGENT_ID=<your-agent-id>\n"
     "MLPEF_MCP_AGENT_KEY=mlpef_<your-agent-key>\n"
     "# also set the proxy audit identity to the same key:\n"
     "MLPEF_PROXY_AGENT_KEY=mlpef_<your-agent-key>")
H3("Step 2 — start the gateway")
CODE("docker compose --profile mcp up --build -d\n"
     "# MCP gateway is now at:  http://localhost:9000/sse  (SSE)\n"
     "#                or:      http://localhost:9000/mcp  (streamable-http)")
H3("Step 3 — point your client at it (config only)")
P("Most URL-based clients (Cline / Cursor / Continue) take an MCP server entry:")
CODE('{\n'
     '  "mcpServers": {\n'
     '    "mlpef": { "url": "http://localhost:9000/sse" }\n'
     '  }\n'
     '}')
P("LangGraph / LangChain, with zero per-tool code:")
CODE("from langchain_mcp_adapters.client import MultiServerMCPClient\n"
     "client = MultiServerMCPClient(\n"
     "    {\"mlpef\": {\"url\": \"http://localhost:9000/sse\", \"transport\": \"sse\"}})\n"
     "tools = await client.get_tools()   # already governed by MLPEF")
P("Claude Desktop (it launches the server itself — needs a local install):")
CODE('{\n'
     '  "mcpServers": {\n'
     '    "mlpef": {\n'
     '      "command": "python", "args": ["-m", "ingress.mcp_server"],\n'
     '      "cwd": "/path/to/MLPEF/data-plane",\n'
     '      "env": {\n'
     '        "MLPEF_MCP_TRANSPORT": "stdio",\n'
     '        "PYTHONPATH": "/path/to/MLPEF/data-plane",\n'
     '        "MLPEF_CONTROL_PLANE_URL": "http://localhost:8080",\n'
     '        "MLPEF_MCP_AGENT_ID": "<your-agent-id>",\n'
     '        "MLPEF_MCP_AGENT_KEY": "mlpef_<your-agent-key>"\n'
     '      }\n'
     '    }\n'
     '  }\n'
     '}')

H2("7.3  Path B — any agent, via REST (a tiny wrapper)")
P("If your agent runs its own code, wrap the one place it executes a tool so it "
  "asks MLPEF first and only runs on ALLOW:")
CODE("import httpx\n"
     "MLPEF = \"http://localhost:8090\"\n"
     "AGENT_ID, KEY = \"<your-agent-id>\", \"mlpef_<your-agent-key>\"\n\n"
     "class Denied(Exception): ...\n\n"
     "def gate(tool, resource, arguments, approval_token=None):\n"
     "    b = httpx.post(f\"{MLPEF}/v1/execute\",\n"
     "        headers={\"X-Agent-Id\": AGENT_ID, \"X-Agent-Key\": KEY},\n"
     "        json={\"tool\": tool, \"action\": tool, \"resource\": resource,\n"
     "              \"arguments\": arguments,\n"
     "              \"approval_token\": approval_token}, timeout=10.0).json()\n"
     "    if b[\"verdict\"] != \"allow\":\n"
     "        raise Denied(f'{b[\"verdict\"]}: {b[\"reason\"]}')\n"
     "    return b[\"output\"]\n\n"
     "# call gate(...) right before the agent runs each tool")

H2("7.4  Path C — OpenAI-style tool calling")
P("Send the model's tool_calls to the OpenAI-compatible endpoint; feed the returned "
  "messages back. Denied calls return a readable '[mlpef:deny] ...' message:")
CODE("POST http://localhost:8090/openai/v1/tool-calls\n"
     "Headers: X-Agent-Id, X-Agent-Key\n"
     "Body: {\"tool_calls\":[{\"id\":\"...\",\n"
     "        \"function\":{\"name\":\"fs.read\",\"arguments\":\"{...}\"}}]}")

H2("7.5  Verify the real agent is governed")
BULLETS([
    "Have the agent do one safe action -&gt; it works.",
    "Have it try something not on its allowlist -&gt; it is denied.",
    "Open <b>Audit Explorer</b> -&gt; both appear in the log.",
])
SAY("'The agent did not change at all — we simply routed its tools through MLPEF, "
    "and now every action it takes is checked, filtered, and recorded.'")
PB()

# =========================================================================== #
# PART 8 — TROUBLESHOOTING
# =========================================================================== #
H1("Part 8 — Troubleshooting (every gotcha + the fix)")
TABLE([
    ["Symptom", "Cause and exact fix"],
    ["Login fails / 'connection refused'", "The website can't reach the API. Check "
     "control-api is healthy (docker compose ps). On Codespaces, set port 8081 "
     "Public and click GitHub's 'Continue' once."],
    ["CORS error in the browser", "Same as above on Codespaces — it is a "
     "port-forwarding gate, not a code bug. The website proxies the API under /api "
     "so only port 8081 needs to be Public."],
    ["Every call denied: 'audit_failure'", "The proxy is logging AS a different "
     "agent than the one calling (R-17). Set MLPEF_PROXY_AGENT_KEY in .env to the "
     "calling agent's key, then 'docker compose up -d'."],
    ["Every call denied: 'identity_unresolved'", "Wrong API key for that Agent ID. "
     "Use that exact agent's key, or the demo agent's key from .env."],
    ["A profile change seems ignored for a few seconds", "The proxy caches "
     "rulebooks for ~30s. Wait, or it refreshes on the next pull."],
    ["MCP client won't connect", "Try the other transport: '/sse' vs '/mcp'. Make "
     "sure port 9000 is reachable and the gateway profile is up."],
    ["Forgot the admin password", "It is MLPEF_ADMIN_PASSWORD in .env; the seed only "
     "sets it on first run. To reset, 'docker compose down -v' then up (this wipes "
     "the database)."],
], [2.0 * inch, 4.3 * inch])
PB()

# =========================================================================== #
# PART 9 — PRESENTING
# =========================================================================== #
H1("Part 9 — How to present this to others")
H2("9.1  The 60-second pitch")
SAY("'AI agents are getting the power to act — run commands, touch files, spend "
    "money. The danger is that the AI's brain can be tricked into doing something "
    "harmful. MLPEF is a security checkpoint that sits in front of every action an "
    "agent takes and checks it with strict, predictable code that the AI cannot "
    "talk its way around. Safe actions pass, attacks are blocked, risky ones wait "
    "for a human, and everything is recorded in a tamper-proof log.'")
H2("9.2  The story arc for a live audience")
BULLETS([
    "<b>Hook:</b> 'What happens if someone tricks your AI assistant into deleting your files?'",
    "<b>Idea:</b> explain 'assume the AI is hijacked' + the checkpoint analogy (Part 1).",
    "<b>Proof 1:</b> run the one-command self-test — 11/11 (Demo #1).",
    "<b>Proof 2:</b> the live demo — allow, then block two attacks, then the human-approval moment (Demo #2).",
    "<b>Payoff:</b> open the Audit Explorer and click 'verify chain'.",
    "<b>Close:</b> 'And it works with real agents with little or no code' (Demo #3) + the honest limits (Part 10).",
])
H2("9.3  Likely questions (and honest answers)")
TABLE([
    ["Question", "Answer"],
    ["Is it 100% secure?", "No — and we never claim that. It is measurable, layered "
     "defence, and every known gap is written down with a severity."],
    ["What if the agent skips MLPEF?", "Then that action is unguarded. You must force "
     "all tool traffic through the proxy with network rules."],
    ["Does it slow the agent down?", "The decision path (validate + policy) targets "
     "under ~10 ms — measured, not guessed."],
    ["Can a hacked proxy grant itself powers?", "No. The proxy holds only a public "
     "key; it can verify permissions but never create them."],
], [1.8 * inch, 4.5 * inch])
PB()

# =========================================================================== #
# PART 10 — LIMITS
# =========================================================================== #
H1("Part 10 — Honest limits (say these out loud)")
BULLETS([
    "<b>Coverage = routing.</b> MLPEF guards only what flows through it; bypass = unguarded.",
    "<b>No 100%.</b> It reduces and measures risk; it does not eliminate it.",
    "<b>Output filtering is best-effort.</b> Clever new tricks can slip past the "
    "scanner — but injected text still cannot run a tool that policy forbids.",
    "<b>The MCP gateway acts as one agent</b> and its port has no built-in login — "
    "keep it on a trusted network.",
    "<b>Strong isolation needs the sandbox on</b> (and ideally a stronger backend "
    "than plain Docker for hostile code).",
])
P("All of these — and more — live in <b>THREAT_MODEL.md</b>, each with a severity "
  "and a plan. Pointing to that file is the most credible thing you can do in a "
  "demo: it shows the project is honest about what it can and cannot do.")
PB()

# =========================================================================== #
# APPENDIX — CHEAT SHEET
# =========================================================================== #
H1("Appendix — one-page command cheat-sheet")
CODE("# Start / stop\n"
     "cp .env.example .env                 # first time only\n"
     "docker compose up --build -d         # start everything (background)\n"
     "docker compose ps                    # what is running + health\n"
     "docker compose logs -f proxy         # follow a service's logs\n"
     "docker compose down                  # stop (keeps the database)\n"
     "docker compose down -v               # stop AND wipe the database\n\n"
     "# Turn the real sandbox on (privileged - trusted host only)\n"
     "docker compose -f docker-compose.yml -f docker-compose.sandbox.yml up --build\n\n"
     "# Turn the MCP gateway on (for MCP agents)\n"
     "docker compose --profile mcp up --build -d   # http://localhost:9000/sse\n\n"
     "# Prove it works (11 checks)\n"
     "python data-plane/ingress/examples/test_agent.py --admin-pass \"admin\"\n\n"
     "# A single governed call\n"
     "curl -X POST http://localhost:8090/v1/execute \\\n"
     "  -H \"X-Agent-Id: <ID>\" -H \"X-Agent-Key: mlpef_<KEY>\" \\\n"
     "  -H 'Content-Type: application/json' \\\n"
     "  -d '{\"tool\":\"fs.read\",\"action\":\"fs.read\",\n"
     "       \"resource\":\"/work/x\",\"arguments\":{\"path\":\"/work/x\"}}'")
SP(10)
HR()
P("<i>MLPEF is one deterministic enforcement layer in a broader defence-in-depth "
  "program. It makes agent actions governable and auditable; it does not make them "
  "risk-free. Read README.md, ARCHITECTURE.md, DEPLOYMENT.md, AGENT_SETUP.md, and "
  "THREAT_MODEL.md for the full detail.</i>")


# --------------------------------------------------------------------------- #
def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.drawString(0.8 * inch, 0.5 * inch, "MLPEF - Complete Guide & Demo Handbook")
    canvas.drawRightString(letter[0] - 0.8 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


doc = SimpleDocTemplate(
    str(OUT), pagesize=letter,
    leftMargin=0.8 * inch, rightMargin=0.8 * inch,
    topMargin=0.8 * inch, bottomMargin=0.8 * inch,
    title="MLPEF - Complete Guide & Demo Handbook",
    author="MLPEF",
)
doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
print(f"WROTE {OUT}")
