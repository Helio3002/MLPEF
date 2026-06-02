# MLPEF Threat Model

> **Status:** Phase 1 skeleton. This document is maintained continuously: every
> control ships mapped to a threat here, and every gap is logged below as a
> residual risk with a severity. It is a living measurement of defense-in-depth,
> **not** a claim of complete or guaranteed protection.

## 1. Purpose & scope

MLPEF governs what autonomous AI agents are permitted to *do* — the side effects
of tool calls — rather than what they say. This model uses **STRIDE** for the
deterministic system and the **OWASP LLM Top 10** for the agent-specific surface.

In-scope threats called out by the charter:

- **OWASP LLM08 — Excessive Agency** (an agent doing more than it should).
- **Confused Deputy** (a privileged component tricked into acting for an
  unauthorized caller).
- **Prompt-injection-driven tool abuse** (untrusted content steering tool use).
- **HITL-token replay** (reusing a one-time human approval).

Out of scope (documented as residual, not solved): securing the LLM's reasoning,
model alignment, and any traffic that does not transit an MLPEF ingress adapter.

## 2. Core assumption — "Assume Breach"

The LLM reasoning engine is treated as **fully attacker-controlled**. No
prompt/alignment guardrail is trusted. Every guarantee comes from deterministic
code in the proxy. Architecturally we decouple the non-deterministic **Decide**
phase (agent) from the deterministic **Do** phase (proxy). LLM output is only ever
the *subject* of a decision, never an *input* to one.

### Trust boundaries

| Boundary | Untrusted side | Trusted side | Crossing control |
|---|---|---|---|
| Agent → Proxy | agent / LLM | data plane | ingress adapter normalizes to `Intent`; identity from credential, not self-asserted |
| Proxy → Control plane | proxy fleet | control-api | signed config bundle; proxy holds **public** key only |
| Approver (UI) → Proxy | — | control plane mints token | Ed25519-signed, scoped, single-use HITL token |
| Sandbox ↔ Host | executed tool | host | L3 isolation + cgroup limits + egress allowlist |
| Tool output → Agent | tool result | agent | L4 scans/redacts; output is data, not a control channel |

## 3. STRIDE summary

| STRIDE | Primary control(s) | Layer | Status |
|---|---|---|---|
| **S**poofing | Agent credential (API key hash) → identity; admin session + RBAC | Identity | PARTIAL — IMPLEMENTED (P2); mTLS [P8] |
| **T**ampering | Strict input validation (allowlist / jail / argv-only); signed config bundle; hash-chained audit | L1 / Pipeline / L5 | PARTIAL — L1 + audit IMPLEMENTED (P1/P3/P4) |
| **R**epudiation | Append-only, hash-chained audit with correlation IDs | L5 | IMPLEMENTED (P3) |
| **I**nformation disclosure | Output secret/PII scanning + redaction | L4 | PARTIAL — scan/redact IMPLEMENTED (P7); not full DLP (R-4) |
| **D**enial of service | Fail-closed on timeout/exception; sandbox cgroup limits; warm-pool bounds | Pipeline / L3 | PARTIAL — fail-closed (P1) + sandbox limits/timeout IMPLEMENTED (P6) |
| **E**levation of privilege | Default-deny ABAC; per-tool allowlist; HITL token for state-altering actions | L2 | PARTIAL — default-deny + HITL IMPLEMENTED (P1/P5) |

## 4. OWASP LLM Top 10 mapping

| OWASP LLM | Relevance to MLPEF | Control | Status |
|---|---|---|---|
| LLM01 Prompt Injection | Injected instructions try to drive tool calls | L1 allowlist + L2 default-deny bound the blast radius; L4 neutralizes output-as-instructions | PARTIAL — L1 allowlist/jail IMPLEMENTED (P4); L2/L4 [P5/P7] |
| LLM02 Insecure Output Handling | Tool output treated as commands | L4 treats output as untrusted data | PARTIAL — L4 neutralization IMPLEMENTED (P7); heuristic (R-26) |
| LLM06 Sensitive Information Disclosure | Secrets/PII in tool output | L4 secret + PII scanning | IMPLEMENTED (P7); not full DLP (R-4) |
| **LLM08 Excessive Agency** | **Agent attempts actions beyond its grant** | **L1 allowlist + L2 default-deny ABAC + HITL gate + L3 containment** | **PARTIAL — L1 allowlist + L2 default-deny + HITL IMPLEMENTED (P1/P4/P5)** |
| LLM10 Model Theft / abuse of tools | Tool misuse for exfiltration | L2 policy + L3 egress allowlist + L4 filtering | PLANNED (P5/P6/P7) |

## 5. Named threat scenarios

### T-1 Excessive Agency (LLM08)
An injected or misaligned agent attempts a tool/action outside its profile.
**Controls:** L1 rejects unknown tools/fields (allowlist); L2 denies by default
unless an explicit allow matches; destructive actions additionally require HITL.
**Residual:** see R-1 (bypass), R-7 (policy authoring error).

### T-2 Confused Deputy
A valid HITL approval for action A is replayed against action B, or a token
issued for one agent is used by another, to make the privileged proxy act for an
unauthorized request. **Control:** HITL tokens are bound to the exact
`subject + tenant + action + resource`; a mismatch is denied **and** flagged as a
security event, and crucially does **not** consume the token's single-use nonce.
**Status:** IMPLEMENTED + adversarially tested (P1).

### T-3 HITL-token replay
A one-time approval token is captured and re-presented. **Control:** every token
carries a nonce (`jti`) consumed against a `NonceStore`; the second presentation
is denied as `TOKEN_REPLAY`. Tokens are also short-lived (`expires_at`).
**Status:** IMPLEMENTED + adversarially tested (P1). **Residual:** see R-2
(nonce-store scope), R-3 (clock skew leeway).

### T-4 Prompt-injection-driven tool abuse
Untrusted content (web page, file, prior tool output) contains instructions that
steer the agent toward harmful tool calls, or tool output is crafted to look like
instructions. **Controls:** the same deterministic gate (L1/L2) regardless of why
the agent wants the action; L4 neutralizes output-as-instructions before it
returns to the agent. **Status:** PARTIAL — L1 allowlist (P4) + L2 default-deny
(P5) + L4 output neutralization (P7) IMPLEMENTED; neutralization is heuristic
(R-26) and the durable guarantee is that injected text still cannot drive a tool
call past L1/L2.

## 6. Threat → Control matrix

Legend: **[IMPL]** implemented in Phase 1 · **[TEST]** has an adversarial test ·
**[Pn]** planned for phase _n_.

| # | Control | Layer | Threats addressed | Status |
|---|---|---|---|---|
| C-1 | Strict per-tool arg spec (allowlist of fields + kinds) | L1 | T-1, LLM01, Tampering | **[IMPL][TEST]** (P4) |
| C-2 | Tool/argument **allowlist** from resolved profile | L1 | T-1 (LLM08) | **[IMPL][TEST]** (P4) |
| C-3 | Lexical path jail + traversal/encoding rejection | L1 | path-traversal tool abuse | **[IMPL][TEST]** (P4) · symlink [L3/P6] |
| C-4 | `argv`-only construction + metacharacter rejection | L1 | command injection | **[IMPL][TEST]** (P4) |
| C-5 | Default-deny ABAC (`default allow = false`) | L2 | T-1, EoP | **[IMPL][TEST]** native+rego (P5) · WASM build [P8] |
| C-6 | **HITL token**: signed, scoped, single-use, expiring | L2 | T-2, T-3, EoP | **[IMPL][TEST]** (P1) · L2 + control-plane mint wired (P5) |
| C-7 | Asymmetric signing (proxy holds public key only) | L2 | forgery under breach | **[IMPL][TEST]** |
| C-8 | Sandbox hardening (ro-rootfs, cap-drop, no-new-privs, non-root, seccomp) | L3 | containment, EoP | **[IMPL][TEST]** config (P6) · live escape tests need Docker |
| C-9 | cgroup CPU/mem/pids limits + timeout | L3 | DoS, runaway tools | **[IMPL][TEST]** (P6) |
| C-10 | Network off (default) + egress allowlist | L3 | exfiltration | **[IMPL]** network-off (P6) · per-host egress [R-24] |
| C-11 | Output secret/PII scan + redaction (pattern + entropy) | L4 | LLM06, Info disclosure | **[IMPL][TEST]** (P7) · not full DLP (R-4) |
| C-12 | Neutralize output-as-instructions | L4 | T-4, LLM02 | **[IMPL][TEST]** (P7) · heuristic (R-26) |
| C-13 | Append-only hash-chained audit + correlation ID | L5 | Repudiation, tamper-evidence | **[IMPL][TEST]** (P3) |
| C-14 | Unskippable audit on every path incl. deny/error | L5 | Repudiation | [IMPL] emitter fail-closed (P3) · all-paths [P8] |
| C-15 | Fail-closed orchestration (exception/timeout → deny) | Pipeline | DoS, ambiguity | [IMPL] error model · [P8] orchestrator |
| C-16 | Identity resolution from credential; admin RBAC | Identity | Spoofing (T-2 cross-agent) | [IMPL] (P2) · mTLS [P8] |
| C-17 | Config bundle (etag + version) + cache/hot-reload + signing | Pipeline | config tampering, availability | [IMPL] endpoint+etag (P2) · cache/sign [P8] |
| C-18 | Safe-by-default (deny-most) profile at registration | Control plane | T-1 for unconfigured agents | [IMPL] schema (P1) + flow (P2) |

## 7. Residual risk register

Severity reflects impact if the residual is realized, given the rest of the
defense-in-depth stack.

| ID | Residual risk | Severity | Mitigation / plan | Status |
|---|---|---|---|---|
| R-1 | **Gateway bypass** — agents not routed through an MLPEF ingress adapter are entirely unguarded. | HIGH | Document plainly (README); enforce via network policy / egress lockdown at deploy time. Coverage = mandatory ingress, not magic. | Accepted + documented |
| R-2 | In-memory `NonceStore` is per-process; a horizontally-scaled proxy fleet could allow a replay across instances. | MEDIUM | Bind nonce ledger to shared store (Postgres/Redis) with atomic check-and-set. | Open → P2/P8 |
| R-3 | Token verification `leeway_seconds` (clock skew) widens the valid window slightly. | LOW | Default leeway = 0; keep control-plane/proxy clocks synced (NTP). | Accepted |
| R-4 | Output filtering (entropy/pattern) has false negatives; it is not full DLP. | MEDIUM | Implemented P7 (scan + redact); residual FN accepted — layer with provider DLP, tune patterns, add an optional quarantine mode. | Implemented (P7); residual accepted |
| R-5 | Docker is a weaker isolation boundary than a VM/microVM; sandbox escape is conceivable. | MEDIUM–HIGH | `SandboxBackend` interface allows gVisor/Firecracker swap; harden + test escapes. | Open → P6 |
| R-6 | Last-known-good cached config means a revoked/changed policy has a propagation window. | LOW–MEDIUM | Short TTL + explicit invalidation + bundle versioning; fail closed if no cache. | Open → P8 |
| R-7 | Policy authoring error (an over-broad allow) grants excess agency. | MEDIUM | `opa test` in CI; "N agents affected" preview before profile edits; default-deny floor. | Open → P5/P10 |
| R-8 | Control-plane **signing key** compromise lets an attacker mint approval tokens. | HIGH | Store in secret manager/HSM; rotate; never on the proxy; restrict minting RBAC. | Open → P2 |
| R-9 | The LLM remains attacker-controlled by design. | (by design) | All guarantees are deterministic and downstream of the model; never trust model output as a decision input. | Accepted |
| R-10 | Side/covert channels out of the sandbox (timing, resource). | LOW | cgroup limits; minimal egress; document. | Accepted → P6 |
| R-11 | Admin session bearer tokens: no rotation/CSRF protection yet; theft replays until expiry. | MEDIUM | Short TTL; HTTPS-only; rotation + CSRF/SameSite handling with the UI. | Open → P10 |
| R-12 | Config bundle is not yet cryptographically signed; the proxy trusts transport (TLS) only. | MEDIUM | Sign the bundle with the control-plane key (reuse token lib); proxy verifies. | Open → P8 |
| R-13 | Seed uses default admin password `admin` if `MLPEF_ADMIN_PASSWORD` is unset. | HIGH (ops) | Seed warns loudly; deploy docs require setting it; no default in compose/prod. | Mitigated + documented |
| R-14 | Agent API keys are stored as plain SHA-256 (no slow hash). | LOW | Acceptable for 256-bit random keys (no brute-force surface); a slow hash would be required only for low-entropy secrets. | Accepted |
| R-15 | `Agent.tenant` and `PolicyProfile.tenant` are not enforced to match; an admin can assign a cross-tenant profile. | LOW | Enforce tenant alignment at registration/assignment in P8; RBAC already gates who can assign. | Open → P8 |
| R-16 | Audit append reads the tail then inserts; concurrent appends from a scaled control-plane could race `seq`/`prev_hash` and fork the chain. | MEDIUM | Serialize appends (SELECT … FOR UPDATE on the tail / single-writer queue / DB sequence) and re-verify on conflict. | Open → P8 |
| R-17 | The emitter→store hop is trusted to TLS; the chain detects tampering only once records are in the store, not a forged/dropped emit in transit. | MEDIUM | Authenticate the proxy to the store; optionally sign events at the emitter (reuse the token lib). Post-store edits are still detected. | Open → P8 |
| R-18 | Whole-chain verification is O(n) — it recomputes every record. | LOW | Periodic checkpoint/anchor hashes; verify in segments. | Open |
| R-19 | The chain is tamper-**evident**, not tamper-**proof** — an attacker with store-write access could rewrite the entire chain consistently. | MEDIUM | Ship to append-only/WORM storage; publish periodic anchor hashes off-system (notary / transparency log). | Documented |
| R-20 | Layer 1's path jail is **lexical** (no I/O): it does not resolve symlinks, so a symlink *inside* the jail pointing outside is not caught at L1. | MEDIUM | True path containment is enforced by the L3 sandbox (read-only rootfs, jailed mount, no symlink-follow); L1 stays I/O-free for the hot path. | By design → P6 |
| R-21 | L1 URL validation is structural only (scheme/host/encoding); it does not enforce a host/egress allowlist. | LOW | Host allowlist (L2 policy) + egress allowlist (L3 sandbox) enforce destination control. | Open → P5/P6 |
| R-22 | Dev signing key is **ephemeral** when `MLPEF_HITL_PRIVATE_KEY_PEM` is unset — tokens do not survive a control-plane restart, and the key is not backed up. | LOW (dev) | Supply the key from a secret manager / HSM in production (see R-8); ephemeral only for local dev, with a startup warning. | Mitigated + documented |
| R-23 | The native L2 engine and the Rego/WASM policy must stay semantically in sync; drift could allow/deny differently in dev vs prod. | MEDIUM | `authz_test.rego` and the Python L2 tests assert the same cases; a CI cross-check evaluating both over shared fixtures is the durable fix. | Open → P8/P11 |
| R-24 | L3 network control is on/off (`network_mode=none`); a per-host egress *allowlist* is not yet enforced when networking is enabled. | MEDIUM | Default-off; when enabled, route via a filtering proxy / firewalled network namespace and enforce the profile's egress allowlist there. | Open → P6/P8 |
| R-25 | userns remapping is a Docker *daemon* setting (`--userns-remap`), not a per-container run flag; the backend runs non-root but relies on deploy config for the user-namespace boundary. | MEDIUM | Enable `--userns-remap` on the daemon; document; consider gVisor/Firecracker (R-5) for a stronger boundary. | Open → deploy/P6 |
| R-26 | L4 injection neutralization is heuristic (regex markers); novel phrasings evade it (false negatives). | MEDIUM | Durable guarantee is upstream — injected text cannot drive a tool call past the L1 allowlist + L2 default-deny. Tune patterns; treat output strictly as data. | Accepted + documented |
| R-27 | Entropy-based secret detection can over-redact legitimate high-entropy data (hashes, IDs) — false positives. | LOW | Tunable `secret_entropy_threshold`; explicit pattern matches run first; document. | Accepted |

## 8. Change log

- **Phase 1:** Established trust boundaries, STRIDE/LLM mappings, named threats,
  and the threat→control matrix. Implemented and adversarially tested the HITL
  token control (C-6, C-7) and the fail-closed error→decision model (C-15
  foundation). Recorded residual risks R-1…R-10.
- **Phase 2:** Control-plane core. Implemented identity resolution + admin RBAC
  (C-16), the config-bundle endpoint with etag/version (C-17), and the
  safe-by-default registration flow (C-18). Credentials stored hashed (PBKDF2 for
  admin passwords, SHA-256 for agent keys); config-bundle pull is fail-closed
  (denies on missing profile / bad credential). Added residual risks R-11…R-15
  (session-token hardening, bundle signing, default password, key hashing,
  tenant alignment).
- **Phase 3:** Layer 5 audit. Implemented the tamper-evident hash chain
  (`common.audit`: AuditEvent/AuditRecord, deterministic `seal` + `verify_chain`)
  with unit + adversarial tamper tests (C-13). Added the control-plane audit store
  (server-sealed append, filtered query, chain-verification endpoint with
  end-to-end tamper-detection test) and the fail-closed data-plane emitter (C-14,
  unskippable). Added residual risks R-16…R-19 (append serialization, emitter
  transport, O(n) verify, WORM/anchoring).
- **Phase 4:** Layer 1 input validation. Implemented the profile-driven tool
  allowlist, strict per-tool argument specs (unknown fields rejected), the lexical
  path jail (rejects `..`, percent-encoding, backslashes, NUL/control, absolute +
  prefix-confusion escapes), and argv-only command validation with a command
  allowlist + metacharacter rejection for literal fields (C-1…C-4) — all
  fail-closed, with adversarial tests for each. Added residual risks R-20 (lexical
  jail; symlink containment at L3) and R-21 (URL host/egress allowlist at L2/L3).
- **Phase 5:** Layer 2 policy + HITL. Implemented default-deny ABAC as Rego
  (`policies/authz.rego` + `opa test`) and an identical native in-process
  `PolicyEngine` (C-5), and wired the HITL approval-token verifier into Layer 2 —
  a permitted destructive action needs a scoped/single-use/expiring token, with
  replay/scope/expiry denials flagged as security events (C-6). Added the
  control-plane HITL queue (agent opens request → approver approves → Ed25519
  token minted, or deny) + public-key endpoint, with an end-to-end mint→verify
  test. Added residual risks R-22 (ephemeral dev signing key) and R-23 (native↔WASM
  policy parity).
- **Phase 6:** Layer 3 sandbox. Implemented the `SandboxBackend` interface and a
  hardened `DockerSandbox` (read-only rootfs, cap-drop ALL, no-new-privileges,
  non-root, default seccomp, CPU/mem/pids cgroup limits, network-off, tmpfs
  scratch) with the warm-pool manager (prewarm → one-shot checkout → destroy →
  refill, latency measured) and a fail-closed executor (C-8/C-9/C-10). Unit-tested
  the hardening config, pool, and executor without a daemon; Docker escape/limit
  tests run when a daemon is present. Added residual risks R-24 (per-host egress
  allowlist) and R-25 (userns remap is daemon-level).
- **Phase 7:** Layer 4 output filtering. Implemented secret scanning (AWS/GitHub/
  Slack/JWT/private-key/assignment patterns + Shannon-entropy detection), PII
  redaction (email/SSN/phone/credit-card per profile categories), and
  prompt-injection neutralization of output-as-instructions (C-11/C-12), with
  unit tests. Secrets/injection in output flag a `security_event`; the layer fails
  closed (deny + empty output) if a scanner errors. Added residual risks R-26
  (injection neutralization is heuristic) and R-27 (entropy over-redaction).
