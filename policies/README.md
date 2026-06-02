# Policies (OPA / Rego)

Layer 2 policy lives here. Populated in **Phase 5**.

Plan:

- Author ABAC policy in Rego with a `default allow = false` floor.
- `opa test` runs the policy unit tests in CI (full OPA, off the hot path).
- `opa build -t wasm` compiles the policy to WASM; the proxy evaluates it
  **in-process, in-memory** on the decision hot path (no network hop), to meet
  the < 10 ms p99 decision-path budget.

`PolicyProfile.rego_policy_ref` (see `common/profiles.py`) holds the logical name
of the policy a profile uses, e.g. `mlpef.authz/default_deny`. The default-deny
floor applies regardless of the referenced policy.

Build artifacts (`*.wasm`, `bundle/`) are produced by the build and are
git-ignored — they are never committed raw.
