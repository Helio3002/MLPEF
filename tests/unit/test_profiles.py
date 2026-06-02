"""Tests that the safe-by-default profile is genuinely deny-most."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from common import (
    ConfigBundle,
    PolicyProfile,
    SandboxLimits,
    default_locked_down_profile,
)


def test_default_profile_is_deny_most() -> None:
    profile = default_locked_down_profile("tenant-a")
    assert profile.tool_allowlist == []
    assert profile.resource_scopes == []
    assert profile.hitl_rules == []
    # Hardened sandbox floor.
    assert profile.sandbox_limits.network_enabled is False
    assert profile.sandbox_limits.read_only_rootfs is True
    assert profile.sandbox_limits.drop_all_capabilities is True
    assert profile.sandbox_limits.no_new_privileges is True
    # Output filtering on by default.
    assert profile.output_filter.scan_secrets is True
    assert profile.output_filter.neutralize_injection is True


def test_sandbox_limits_safe_defaults() -> None:
    limits = SandboxLimits()
    assert limits.network_enabled is False
    assert limits.egress_allowlist == []
    assert limits.read_only_rootfs is True


def test_sandbox_limits_reject_nonpositive_resources() -> None:
    with pytest.raises(ValidationError):
        SandboxLimits(memory_mb=0)
    with pytest.raises(ValidationError):
        SandboxLimits(timeout_seconds=-1)


def test_profile_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        PolicyProfile(
            profile_id="p1",
            name="p",
            tenant="t",
            rogue_field=True,  # type: ignore[call-arg]
        )


def test_config_bundle_round_trip() -> None:
    profile = default_locked_down_profile("tenant-a")
    bundle = ConfigBundle(
        agent_id="agent-1",
        profile=profile,
        issued_at=1_700_000_000,
        etag="abc123",
    )
    assert bundle.profile.profile_id == "default-locked-down"
    # JSON round-trip keeps the nested profile intact.
    restored = ConfigBundle.model_validate_json(bundle.model_dump_json())
    assert restored == bundle
