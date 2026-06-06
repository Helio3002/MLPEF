"""Assemble a `Proxy` from the environment.

Shared by both runnable entrypoints — the HTTP ingress app (`proxy.server`) and
the MCP gateway server (`ingress.mcp_server`) — so they wire identical enforcement
(config-bundle signature verification, single-use nonce store, audit sink, sandbox
policy). This module has **no import-time side effects** (it defines functions
only), so importing it never builds a proxy or touches the network until you call
`build_proxy()`.

**Sandbox is opt-in.** By default (`MLPEF_SANDBOX_ENABLED` unset/false) the command
builder returns ``None`` for every tool, so L3/L4 are skipped and no tool executes
code — L1/L2/L5 (validation, default-deny ABAC, HITL token enforcement, unskippable
audit) are fully live and no Docker is required. Set `MLPEF_SANDBOX_ENABLED=true`
(with a mounted Docker socket) to run code-executing tools in a hardened, ephemeral
container and filter their output (L3/L4). See THREAT_MODEL.md R-30.
"""

from __future__ import annotations

import os
import sys
import time

import httpx
from common import (
    AuditEvent,
    InMemoryNonceStore,
    Intent,
    NonceStore,
    SandboxLimits,
    load_public_key_pem,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from layer3_sandbox import DockerSandboxBackend, WarmPool
from layer5_audit import Auditor, AuditSink, HttpAuditSink

from .config_cache import ConfigCache
from .http_config import HttpConfigFetcher
from .nonce_store import HttpNonceStore
from .pipeline import CommandBuilder, Pipeline, default_command_builder
from .proxy import Proxy


def _env(name: str, default: str) -> str:
    return os.getenv(name) or default


class StdoutAuditSink:
    """Dev/demo sink: prints a one-line summary of every audit event.

    Never raises on a well-formed event, so it does not spuriously trip the
    pipeline's fail-closed audit guard. Use `HttpAuditSink` for the real store.
    """

    def emit(self, event: AuditEvent) -> None:
        flag = " SECURITY-EVENT" if event.security_event else ""
        code = event.reason_code.value if event.reason_code is not None else "-"
        print(
            f"[audit] {event.correlation_id} {event.agent_id} "
            f"{event.action} {event.resource} -> {event.final_verdict.value} "
            f"({code}){flag}",
            file=sys.stdout,
            flush=True,
        )


def _fetch_public_key(control_plane_url: str) -> Ed25519PublicKey:
    """Return the control plane's HITL verification key.

    Prefers an explicitly-provided PEM (`MLPEF_HITL_PUBLIC_KEY_PEM`); otherwise
    fetches it from the PUBLIC `/hitl/public-key` endpoint, retrying so the proxy
    can start before the control plane is fully up (compose ordering). Fails
    closed (raises) if the key never arrives — a proxy without the right key
    cannot honor HITL approvals or verify config signatures.
    """
    explicit = os.getenv("MLPEF_HITL_PUBLIC_KEY_PEM")
    if explicit:
        return load_public_key_pem(explicit.encode("utf-8"))

    retries = int(_env("MLPEF_PUBLIC_KEY_FETCH_RETRIES", "15"))
    delay = float(_env("MLPEF_PUBLIC_KEY_FETCH_DELAY", "2.0"))
    url = f"{control_plane_url.rstrip('/')}/hitl/public-key"
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            response = httpx.get(url, timeout=5.0)
            response.raise_for_status()
            pem = response.json()["public_key_pem"]
            print(f"[server] fetched HITL public key from {url}", file=sys.stderr)
            return load_public_key_pem(pem.encode("utf-8"))
        except Exception as exc:  # transport / not-up-yet / malformed
            last_error = exc
            print(
                f"[server] public-key fetch attempt {attempt}/{retries} failed: {exc}",
                file=sys.stderr,
            )
            if attempt < retries:
                time.sleep(delay)
    raise RuntimeError(
        f"could not fetch HITL public key from {url} after {retries} attempts: {last_error}"
    )


def _build_audit_sink() -> AuditSink:
    audit_url = os.getenv("MLPEF_AUDIT_URL")
    audit_key = os.getenv("MLPEF_AUDIT_AGENT_KEY")
    if audit_url and audit_key:
        print(f"[server] auditing to control-plane store at {audit_url}", file=sys.stderr)
        return HttpAuditSink(audit_url, audit_key)
    print("[server] auditing to stdout (set MLPEF_AUDIT_URL + _AGENT_KEY for the store)",
          file=sys.stderr)
    return StdoutAuditSink()


def _build_nonce_store() -> NonceStore:
    nonce_url = os.getenv("MLPEF_NONCE_URL")
    nonce_key = os.getenv("MLPEF_NONCE_AGENT_KEY")
    if nonce_url and nonce_key:
        print(f"[server] single-use nonces via control-plane ledger at {nonce_url}",
              file=sys.stderr)
        return HttpNonceStore(nonce_url, nonce_key)
    # In-process is correct for a single instance; a scaled fleet MUST set
    # MLPEF_NONCE_URL so single-use holds across instances (R-2).
    print("[server] single-use nonces in-process (set MLPEF_NONCE_URL for a scaled fleet)",
          file=sys.stderr)
    return InMemoryNonceStore()


def _no_sandbox(_intent: Intent) -> list[str] | None:
    """Disabled-sandbox command builder: never executes code (L3/L4 skipped)."""
    return None


def _build_sandbox() -> tuple[WarmPool, CommandBuilder]:
    """Return the sandbox pool + command builder, gated by MLPEF_SANDBOX_ENABLED.

    Disabled (default): a size-0 pool + a builder that returns None, so no tool
    executes and Docker is never contacted. Enabled: a pre-warmed pool over the
    Docker backend + the real command builder — requires a mounted Docker socket
    (privileged; see the docker-compose.sandbox.yml overlay and THREAT_MODEL R-30).
    """
    if _env("MLPEF_SANDBOX_ENABLED", "false").lower() not in ("1", "true", "yes", "on"):
        pool = WarmPool(DockerSandboxBackend(), image="alpine", limits=SandboxLimits(), size=0)
        return pool, _no_sandbox

    image = _env("MLPEF_SANDBOX_IMAGE", "alpine")
    size = int(_env("MLPEF_SANDBOX_POOL_SIZE", "2"))
    print(
        f"[server] sandbox ENABLED: image={image} pool={size} — requires a mounted "
        "Docker socket (privileged; see THREAT_MODEL R-30)",
        file=sys.stderr,
    )
    pool = WarmPool(DockerSandboxBackend(), image=image, limits=SandboxLimits(), size=size)
    return pool, default_command_builder


def build_proxy() -> Proxy:
    """Assemble a fully-wired `Proxy` from the environment (fetches the public key,
    builds the signed-config cache, nonce store, audit sink, and sandbox policy)."""
    control_plane_url = _env("MLPEF_CONTROL_PLANE_URL", "http://control-api:8080")
    ttl_seconds = int(_env("MLPEF_CONFIG_TTL_SECONDS", "30"))
    leeway_seconds = int(_env("MLPEF_HITL_LEEWAY_SECONDS", "0"))

    public_key = _fetch_public_key(control_plane_url)
    # Verify each bundle's signature before the proxy applies it (R-12): config is
    # authenticated, not just trusted via TLS.
    cache = ConfigCache(
        HttpConfigFetcher(control_plane_url, public_key=public_key),
        ttl_seconds=ttl_seconds,
    )
    pool, command_builder = _build_sandbox()
    pipeline = Pipeline(
        public_key=public_key,
        nonce_store=_build_nonce_store(),
        sandbox_pool=pool,
        auditor=Auditor(_build_audit_sink()),
        command_builder=command_builder,
        leeway_seconds=leeway_seconds,
    )
    print(f"[server] proxy ready; control plane = {control_plane_url}", file=sys.stderr)
    return Proxy(config_cache=cache, pipeline=pipeline)
