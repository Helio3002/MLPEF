"""HTTP config fetcher — pulls a ConfigBundle from the control plane.

A 401/403 maps to IdentityUnresolved (credential rejected -> the cache must not
serve stale config). Other transport/HTTP errors propagate so the cache can fall
back to last-known-good. httpx is imported lazily so the package stays importable
without the proxy extra installed.

When a `public_key` is supplied, the fetched bundle's Ed25519 signature is
verified before it is returned — the proxy refuses to apply config it cannot
authenticate as coming from the control plane (R-12, fail closed). A verification
failure raises `ConfigBundleUntrusted`, which the cache handles like any fetch
failure (serve verified last-known-good if present, else deny); the untrusted
bundle is never cached.
"""

from __future__ import annotations

from common import ConfigBundle, IdentityUnresolved, verify_config_bundle
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class HttpConfigFetcher:
    def __init__(
        self,
        base_url: str,
        *,
        public_key: Ed25519PublicKey | None = None,
        timeout: float = 2.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._public_key = public_key
        self._timeout = timeout

    def fetch(self, agent_id: str, credential: str) -> ConfigBundle:
        import httpx

        url = f"{self._base_url}/agents/{agent_id}/config-bundle"
        response = httpx.get(url, headers={"X-Agent-Key": credential}, timeout=self._timeout)
        if response.status_code in (401, 403):
            raise IdentityUnresolved("agent credential rejected by the control plane")
        response.raise_for_status()
        bundle = ConfigBundle.model_validate(response.json())
        if self._public_key is not None:
            # Raises ConfigBundleUntrusted on an absent/forged signature (fail closed).
            verify_config_bundle(bundle, self._public_key)
        return bundle
