"""Docker sandbox backend.

`build_container_kwargs` is a pure function (no Docker import) that turns the
profile's SandboxLimits into a hardened container spec — it is unit-tested without
a daemon. `DockerSandboxBackend`/`DockerSandbox` use it and lazily import the
Docker SDK, so this module imports fine without `docker` installed and the rest of
Layer 3 is testable via a fake backend.

Hardening applied: read-only rootfs, all capabilities dropped, no-new-privileges,
non-root user, default seccomp (never disabled), CPU/memory/pids cgroup limits,
network off by default, and a small noexec/nosuid tmpfs scratch.
"""

from __future__ import annotations

import contextlib
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any

from common import SandboxLimits
from common.errors import ResourceLimitExceeded, SandboxError
from common.timing import monotonic_ms

from .backend import SandboxResult

# 65534:65534 is the conventional nobody:nogroup — a non-root, unprivileged uid.
_NOBODY = "65534:65534"


def build_container_kwargs(image: str, limits: SandboxLimits) -> dict[str, Any]:
    """Translate SandboxLimits into hardened `docker run` kwargs."""
    security_opt = ["no-new-privileges:true"]
    # "default" => rely on the daemon's default seccomp profile (do NOT disable it).
    # A custom profile path/json is passed through; "unconfined" is never emitted.
    if limits.seccomp_profile not in ("", "default", "unconfined"):
        security_opt.append(f"seccomp={limits.seccomp_profile}")

    kwargs: dict[str, Any] = {
        "image": image,
        "detach": True,
        "read_only": limits.read_only_rootfs,
        "cap_drop": ["ALL"] if limits.drop_all_capabilities else [],
        "security_opt": security_opt,
        "network_mode": "bridge" if limits.network_enabled else "none",
        "mem_limit": f"{limits.memory_mb}m",
        "nano_cpus": limits.cpu_millicores * 1_000_000,  # 1 millicore = 1e6 nanocpus
        "pids_limit": limits.pids,
        "tmpfs": {"/tmp": "rw,noexec,nosuid,size=64m"},
        "working_dir": "/work",
    }
    if limits.run_as_non_root:
        kwargs["user"] = _NOBODY
    return kwargs


def _decode(data: bytes | None) -> str:
    return data.decode("utf-8", errors="replace") if data else ""


class DockerSandbox:
    def __init__(self, container: Any, idle_timeout_default: int = 30) -> None:
        self._container = container
        self.id = str(container.id)
        self._default_timeout = idle_timeout_default

    def run(self, argv: list[str], *, timeout_seconds: int) -> SandboxResult:
        start = monotonic_ms()
        # exec_run has no native timeout; bound it with a worker + future timeout.
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self._container.exec_run, argv, demux=True)
            try:
                exec_result = future.result(timeout=timeout_seconds)
            except FuturesTimeoutError:
                return SandboxResult(
                    exit_code=-1, stdout="", stderr="", timed_out=True,
                    elapsed_ms=monotonic_ms() - start,
                )
            except Exception as exc:  # docker / transport failure
                raise SandboxError("sandbox exec failed") from exc

        stdout_bytes, stderr_bytes = exec_result.output
        try:
            self._container.reload()
            if self._container.attrs.get("State", {}).get("OOMKilled"):
                raise ResourceLimitExceeded("sandbox exceeded its memory limit")
        except ResourceLimitExceeded:
            raise
        except Exception:  # reload is best-effort; absent OOM info is not a failure
            pass
        return SandboxResult(
            exit_code=exec_result.exit_code or 0,
            stdout=_decode(stdout_bytes),
            stderr=_decode(stderr_bytes),
            timed_out=False,
            elapsed_ms=monotonic_ms() - start,
        )

    def destroy(self) -> None:
        # Cleanup is best-effort — a removed/absent container is not an error.
        with contextlib.suppress(Exception):
            self._container.remove(force=True)


class DockerSandboxBackend:
    def __init__(self, *, idle_seconds: int = 3600, client: Any = None) -> None:
        self._idle_seconds = idle_seconds
        self._client = client

    def _get_client(self) -> Any:
        if self._client is None:
            import docker  # lazy: keep this module importable without the SDK

            self._client = docker.from_env()
        return self._client

    def create(self, limits: SandboxLimits, *, image: str) -> DockerSandbox:
        client = self._get_client()
        kwargs = build_container_kwargs(image, limits)
        try:
            # Start an idle, warm container; tool argv is exec'd into it on demand.
            container = client.containers.run(command=["sleep", str(self._idle_seconds)], **kwargs)
        except Exception as exc:
            raise SandboxError("failed to create sandbox container") from exc
        return DockerSandbox(container)
