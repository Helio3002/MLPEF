"""The Docker hardening spec is built correctly (no daemon needed)."""

from __future__ import annotations

from common import SandboxLimits

from layer3_sandbox import build_container_kwargs


def test_default_hardening_flags() -> None:
    kwargs = build_container_kwargs("python:3.12-slim", SandboxLimits())
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in kwargs["security_opt"]
    assert kwargs["network_mode"] == "none"
    assert kwargs["user"] == "65534:65534"
    assert kwargs["mem_limit"] == "256m"
    assert kwargs["nano_cpus"] == 500 * 1_000_000
    assert kwargs["pids_limit"] == 128
    assert "/tmp" in kwargs["tmpfs"]


def test_default_seccomp_is_not_disabled() -> None:
    # "default" must rely on the daemon profile, never emit seccomp=unconfined.
    kwargs = build_container_kwargs("img", SandboxLimits())
    assert not any("unconfined" in opt for opt in kwargs["security_opt"])
    assert not any(opt.startswith("seccomp=") for opt in kwargs["security_opt"])


def test_network_enabled_changes_mode() -> None:
    kwargs = build_container_kwargs("img", SandboxLimits(network_enabled=True))
    assert kwargs["network_mode"] != "none"


def test_custom_resource_limits_applied() -> None:
    limits = SandboxLimits(memory_mb=512, cpu_millicores=250, pids=64)
    kwargs = build_container_kwargs("img", limits)
    assert kwargs["mem_limit"] == "512m"
    assert kwargs["nano_cpus"] == 250 * 1_000_000
    assert kwargs["pids_limit"] == 64
