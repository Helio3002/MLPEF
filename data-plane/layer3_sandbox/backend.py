"""Sandbox backend contract.

A `Sandbox` is a single, hardened, ephemeral execution environment. It is created
warm (idle), used for exactly one tool invocation, and then destroyed — never
reused across requests. `SandboxBackend` produces them; the Docker backend is the
reference implementation, and a VM/microVM backend (gVisor/Firecracker) can be
swapped in behind this same interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from common import SandboxLimits


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    elapsed_ms: float


@runtime_checkable
class Sandbox(Protocol):
    """A live, single-use sandbox instance."""

    id: str

    def run(self, argv: list[str], *, timeout_seconds: int) -> SandboxResult: ...

    def destroy(self) -> None: ...


@runtime_checkable
class SandboxBackend(Protocol):
    """Creates warm, hardened sandboxes from the profile's limits."""

    def create(self, limits: SandboxLimits, *, image: str) -> Sandbox: ...
