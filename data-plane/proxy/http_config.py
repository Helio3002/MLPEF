"""HTTP config fetcher — pulls a ConfigBundle from the control plane.

A 401/403 maps to IdentityUnresolved (credential rejected -> the cache must not
serve stale config). Other transport/HTTP errors propagate so the cache can fall
back to last-known-good. httpx is imported lazily so the package stays importable
without the proxy extra installed.
"""

from __future__ import annotations

from common import ConfigBundle, IdentityUnresolved


class HttpConfigFetcher:
    def __init__(self, base_url: str, *, timeout: float = 2.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def fetch(self, agent_id: str, credential: str) -> ConfigBundle:
        import httpx

        url = f"{self._base_url}/agents/{agent_id}/config-bundle"
        response = httpx.get(url, headers={"X-Agent-Key": credential}, timeout=self._timeout)
        if response.status_code in (401, 403):
            raise IdentityUnresolved("agent credential rejected by the control plane")
        response.raise_for_status()
        return ConfigBundle.model_validate(response.json())
