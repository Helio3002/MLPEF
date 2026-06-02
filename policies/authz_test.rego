# `opa test policies/` runs these. They pin the default-deny semantics that the
# NativePolicyEngine (data-plane/layer2_policy) must match.
package mlpef.authz_test

import rego.v1

import data.mlpef.authz

profile := {
	"tool_allowlist": ["fs.read", "fs.delete"],
	"hitl_rules": [{"action_pattern": "fs.delete", "resource_pattern": "*"}],
}

test_denies_tool_not_in_allowlist if {
	authz.decision == "deny" with input as {
		"tool": "net.connect",
		"action": "net.connect",
		"resource": "1.2.3.4",
		"profile": profile,
	}
}

test_allows_permitted_non_destructive_tool if {
	authz.decision == "allow" with input as {
		"tool": "fs.read",
		"action": "fs.read",
		"resource": "/work/agent/notes.txt",
		"profile": profile,
	}
}

test_requires_hitl_for_destructive_action if {
	authz.decision == "hitl_required" with input as {
		"tool": "fs.delete",
		"action": "fs.delete",
		"resource": "/work/agent/notes.txt",
		"profile": profile,
	}
}

test_denies_when_allowlist_empty if {
	authz.decision == "deny" with input as {
		"tool": "fs.read",
		"action": "fs.read",
		"resource": "/work/agent/notes.txt",
		"profile": {"tool_allowlist": [], "hitl_rules": []},
	}
}
