# Policies (OPA / Rego)

Layer 2 policy lives here (authored in **Phase 5**).

- `authz.rego` — default-deny ABAC: classifies each action as `deny` / `allow` /
  `hitl_required` from the agent's resolved profile (tool allowlist + HITL rules).
- `authz_test.rego` — `opa test` cases that pin the semantics.

Run / build (in the Codespace, with `opa` installed):

```bash
opa test policies/                                 # policy unit tests
opa build -t wasm -e mlpef/authz/decision policies/   # -> bundle.tar.gz (policy.wasm)
```

The compiled `policy.wasm` is evaluated **in-process** on the decision hot path
(no network hop) to meet the < 10 ms p99 budget. Until that artifact is wired in
(Phase 8), the data-plane `NativePolicyEngine` (`data-plane/layer2_policy/`)
provides the identical default-deny classification in pure Python behind the same
`PolicyEngine` interface; `authz_test.rego` and the Python tests assert the same
cases, keeping them in lockstep.

The Ed25519 signature check on the HITL approval token is **not** done in
Rego/WASM (OPA cannot verify signatures): the proxy verifies the token in Python
(`common.verify_hitl_token`) after the policy classifies an action as
`hitl_required`.

`PolicyProfile.rego_policy_ref` (see `common/profiles.py`) holds the logical name
of the policy a profile uses, e.g. `mlpef.authz/default_deny`. The default-deny
floor applies regardless of the referenced policy.

Build artifacts (`*.wasm`, `bundle/`) are produced by the build and are
git-ignored — they are never committed raw.
