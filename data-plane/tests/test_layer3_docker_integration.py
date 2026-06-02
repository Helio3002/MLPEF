"""Real Docker hardening checks (escape/limit). Auto-skipped without a daemon.

These run in environments where Docker is available (e.g. the Codespace). They
exercise the actual container hardening; assertions are kept loose to tolerate
Docker-version differences.
"""

from __future__ import annotations

import pytest

docker = pytest.importorskip("docker")

from common import SandboxLimits  # noqa: E402 - after importorskip by design
from layer3_sandbox import DockerSandboxBackend  # noqa: E402

IMAGE = "busybox:latest"


def _docker_available() -> bool:
    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        return False
    return True


pytestmark = pytest.mark.skipif(not _docker_available(), reason="no Docker daemon available")


def test_readonly_rootfs_blocks_root_writes() -> None:
    backend = DockerSandboxBackend()
    sandbox = backend.create(SandboxLimits(), image=IMAGE)
    try:
        result = sandbox.run(
            ["sh", "-c", "touch /probe && echo WROTE || echo BLOCKED"], timeout_seconds=15
        )
        assert "BLOCKED" in result.stdout
    finally:
        sandbox.destroy()


def test_runs_as_non_root() -> None:
    backend = DockerSandboxBackend()
    sandbox = backend.create(SandboxLimits(), image=IMAGE)
    try:
        result = sandbox.run(["id", "-u"], timeout_seconds=15)
        assert result.stdout.strip() == "65534"
    finally:
        sandbox.destroy()


def test_network_is_off_by_default() -> None:
    backend = DockerSandboxBackend()
    sandbox = backend.create(SandboxLimits(), image=IMAGE)
    try:
        result = sandbox.run(
            ["sh", "-c", "wget -T 2 -q -O - http://1.1.1.1 || echo NO_NET"], timeout_seconds=20
        )
        assert "NO_NET" in result.stdout
    finally:
        sandbox.destroy()
