"""Runnable proxy entrypoint — wires a Proxy from the environment and serves it.

This is the data-plane process that `docker compose` runs (`uvicorn
proxy.server:app`). It assembles the real components:

  * **identity + config** — `HttpConfigFetcher` → `ConfigCache` (TTL, hot-reload,
    last-known-good) pointed at the control plane.
  * **HITL verification key** — fetched once at startup from the control plane's
    PUBLIC `GET /hitl/public-key`; the proxy holds the public key only and can
    verify tokens but never mint them (assume-breach). Boot fails closed if the
    key cannot be obtained.
  * **audit** — events go to stdout by default (visible in `docker logs`); set
    `MLPEF_AUDIT_URL` + `MLPEF_AUDIT_AGENT_KEY` to POST them to the control-plane
    store instead (see THREAT_MODEL.md R-17: per-agent audit auth from a shared
    proxy is a known residual).

**Demo limitation — the sandbox is disabled here.** The command builder returns
``None`` for every tool, so L3/L4 are skipped and no tool actually executes code.
Running real containers needs Docker-in-Docker / a mounted socket, which is a
privileged setup we deliberately keep out of the default compose (THREAT_MODEL.md
R-29). L1/L2/L5 — validation, the default-deny ABAC core, HITL token enforcement,
and the unskippable audit — are fully live, which is what the end-to-end demo
exercises. Wire a `DockerSandboxBackend` with a real socket + a `command_builder`
to enable execution.
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
    SandboxLimits,
    load_public_key_pem,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI

from ingress.app import create_app
from layer3_sandbox import DockerSandboxBackend, WarmPool
from layer5_audit import Auditor, AuditSink, HttpAuditSink

from .config_cache import ConfigCache
from .http_config import HttpConfigFetcher
from .pipeline import Pipeline
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
    cannot honor HITL approvals.
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


def _no_sandbox(_intent: Intent) -> list[str] | None:
    """Demo command builder: never executes code (L3/L4 skipped). See module docstring."""
    return None


def build_app() -> FastAPI:
    control_plane_url = _env("MLPEF_CONTROL_PLANE_URL", "http://control-api:8080")
    ttl_seconds = int(_env("MLPEF_CONFIG_TTL_SECONDS", "30"))
    leeway_seconds = int(_env("MLPEF_HITL_LEEWAY_SECONDS", "0"))

    public_key = _fetch_public_key(control_plane_url)
    # Pass the public key so the fetcher verifies each bundle's signature before
    # the proxy applies it (R-12): config is authenticated, not just trusted via TLS.
    cache = ConfigCache(
        HttpConfigFetcher(control_plane_url, public_key=public_key),
        ttl_seconds=ttl_seconds,
    )

    # Sandbox disabled for the demo: size-0 pool + a command builder that returns
    # None means `backend.create` is never called, so Docker is never required.
    pool = WarmPool(DockerSandboxBackend(), image="alpine", limits=SandboxLimits(), size=0)

    pipeline = Pipeline(
        public_key=public_key,
        nonce_store=InMemoryNonceStore(),
        sandbox_pool=pool,
        auditor=Auditor(_build_audit_sink()),
        command_builder=_no_sandbox,
        leeway_seconds=leeway_seconds,
    )
    proxy = Proxy(config_cache=cache, pipeline=pipeline)
    print(f"[server] proxy ready; control plane = {control_plane_url}", file=sys.stderr)
    return create_app(proxy)


app = build_app()
