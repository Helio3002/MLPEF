# MLPEF Layer 2 authorization policy (default-deny ABAC).
#
# Produces `decision` in {"deny", "allow", "hitl_required"} from the agent's
# resolved profile. This policy only CLASSIFIES the action; the Ed25519 signature
# check of the HITL approval token is done by the proxy in Python (OPA cannot
# verify signatures). The data-plane NativePolicyEngine mirrors these exact rules,
# and `opa build -t wasm` compiles this for in-process evaluation on the hot path.
package mlpef.authz

import rego.v1

# Floor: nothing is permitted unless a rule below says so.
default decision := "deny"

tool_allowed if input.tool in input.profile.tool_allowlist

requires_hitl if {
	some rule in input.profile.hitl_rules
	glob.match(rule.action_pattern, [], input.action)
	glob.match(rule.resource_pattern, [], input.resource)
}

# A permitted-but-destructive action needs human approval first.
decision := "hitl_required" if {
	tool_allowed
	requires_hitl
}

# A permitted, non-destructive action is allowed outright.
decision := "allow" if {
	tool_allowed
	not requires_hitl
}
