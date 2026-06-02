"""PolicyProfile — the reusable unit that makes central configuration work.

An agent references a `PolicyProfile` by id; editing the profile reconfigures
every agent on it at once (no per-agent manual config). The control plane stores
profiles in Postgres; the proxy receives the resolved `ConfigBundle` from
`GET /agents/{id}/config-bundle`, caches it with a TTL, and hot-reloads on change.

This module is the single source of truth for the *shape* of a profile, shared by
control-api (which authors it) and the proxy (which enforces it). The DB models in
the control plane map onto these types.

Safety posture: an unconfigured agent must still be locked down. The profile
defaults here are deny-most — empty tool allowlist, network off, hardened sandbox,
output filtering on — and `default_locked_down_profile()` is the canonical
safe-by-default profile the registration flow assigns.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ResourceKind(StrEnum):
    PATH = "path"
    URL = "url"
    CUSTOM = "custom"


class SandboxLimits(BaseModel):
    """Layer 3 hardening + cgroup limits, sourced from the profile.

    Defaults are the safe floor: read-only rootfs, all capabilities dropped, no
    new privileges, and networking off. A profile widens this only deliberately.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    cpu_millicores: int = Field(default=500, gt=0)
    memory_mb: int = Field(default=256, gt=0)
    pids: int = Field(default=128, gt=0)
    timeout_seconds: int = Field(default=30, gt=0)

    read_only_rootfs: bool = True
    drop_all_capabilities: bool = True
    no_new_privileges: bool = True
    run_as_non_root: bool = True
    seccomp_profile: str = "default"

    network_enabled: bool = False
    egress_allowlist: list[str] = Field(default_factory=list)


class ResourceScope(BaseModel):
    """Bounds the resources a tool may touch (enforced in Layer 1 / Layer 2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ResourceKind
    # For PATH scopes, realpath canonicalization must stay under this prefix.
    jail_prefix: str | None = None
    # Allowlist of glob/pattern entries. Empty list = nothing in this scope.
    allow_patterns: list[str] = Field(default_factory=list)


class HITLRule(BaseModel):
    """Declares that a matching action requires human approval before execution.

    When Layer 2 matches a rule and no valid approval token is present, it returns
    HITL_REQUIRED and the control plane opens an HITLRequest. The minted token's
    lifetime is `token_ttl_seconds`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_pattern: str
    resource_pattern: str = "*"
    approver_roles: list[str] = Field(default_factory=lambda: ["approver"])
    token_ttl_seconds: int = Field(default=300, gt=0)


class OutputFilterPolicy(BaseModel):
    """Layer 4 output scanning configuration.

    Defense-in-depth, not full DLP — the false-negative risk of entropy/pattern
    scanning is documented in THREAT_MODEL.md as residual risk.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_secrets: bool = True
    secret_entropy_threshold: float = Field(default=4.0, ge=0.0)
    redact_pii: bool = True
    pii_categories: list[str] = Field(default_factory=list)
    # Neutralize tool-output content that resembles instructions to the agent:
    # output is untrusted data, never a control channel.
    neutralize_injection: bool = True


class PolicyProfile(BaseModel):
    """The centrally-managed, reusable policy unit an agent inherits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str
    name: str
    tenant: str
    description: str = ""
    version: int = Field(default=1, ge=1)

    # Empty allowlist = nothing permitted. Allowlist, never denylist.
    tool_allowlist: list[str] = Field(default_factory=list)

    # Logical reference resolved to a compiled WASM policy in Phase 5. Layer 2 is
    # structurally default-deny (`default allow = false`) regardless of this ref.
    rego_policy_ref: str = "mlpef.authz/default_deny"

    resource_scopes: list[ResourceScope] = Field(default_factory=list)
    hitl_rules: list[HITLRule] = Field(default_factory=list)
    sandbox_limits: SandboxLimits = Field(default_factory=SandboxLimits)
    output_filter: OutputFilterPolicy = Field(default_factory=OutputFilterPolicy)


class ConfigBundle(BaseModel):
    """What the proxy caches per agent. Returned by the config-bundle endpoint.

    The control plane may sign the bundle (`signature`) so a proxy can trust
    cached config under the assume-breach model; signature verification is wired
    in Phase 8. `etag`/`bundle_version` drive cache invalidation + hot reload.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    profile: PolicyProfile
    issued_at: int
    bundle_version: int = Field(default=1, ge=1)
    etag: str
    signature: str | None = None


def default_locked_down_profile(
    tenant: str,
    *,
    profile_id: str = "default-locked-down",
    name: str = "Default (locked down)",
) -> PolicyProfile:
    """The canonical safe-by-default profile assigned at agent registration.

    Deny-most: no tools allowed, no resource scopes, hardened sandbox, output
    filtering fully on. An agent on this profile can do nothing until an operator
    deliberately grants capability via the control plane.
    """
    return PolicyProfile(
        profile_id=profile_id,
        name=name,
        tenant=tenant,
        description="Safe-by-default profile: nothing is permitted until granted.",
        tool_allowlist=[],
        rego_policy_ref="mlpef.authz/default_deny",
        resource_scopes=[],
        hitl_rules=[],
        sandbox_limits=SandboxLimits(),
        output_filter=OutputFilterPolicy(),
    )
