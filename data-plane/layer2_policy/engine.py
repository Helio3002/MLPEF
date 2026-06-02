"""Layer 2 policy classification — the default-deny ABAC core.

`classify` returns a Verdict (ALLOW / DENY / HITL_REQUIRED) from the agent's
resolved profile, mirroring `policies/authz.rego` exactly. The WASM-compiled Rego
slots in behind the same `PolicyEngine` protocol in Phase 8; the token signature
check is layered on top in Python (see validator.evaluate).
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Protocol, runtime_checkable

from common import HITLRule, Intent, PolicyProfile, Verdict


def _requires_hitl(rules: list[HITLRule], action: str, resource: str) -> bool:
    # Case-sensitive glob match, mirroring rego glob.match(pattern, [], value).
    return any(
        fnmatchcase(action, rule.action_pattern) and fnmatchcase(resource, rule.resource_pattern)
        for rule in rules
    )


@runtime_checkable
class PolicyEngine(Protocol):
    """Classifies an intent against a profile. Implemented natively now and by a
    WASM-compiled Rego module in production (same interface)."""

    def classify(self, intent: Intent, profile: PolicyProfile) -> Verdict: ...


class NativePolicyEngine:
    """Pure-Python default-deny evaluator (mirror of policies/authz.rego)."""

    def classify(self, intent: Intent, profile: PolicyProfile) -> Verdict:
        if intent.tool not in profile.tool_allowlist:
            return Verdict.DENY  # default-deny floor
        if _requires_hitl(profile.hitl_rules, intent.action, intent.resource):
            return Verdict.HITL_REQUIRED
        return Verdict.ALLOW
