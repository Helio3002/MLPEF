"""Per-agent config-bundle cache: TTL + hot-reload + last-known-good.

The proxy resolves an agent's policy by pulling its `ConfigBundle` from the
control plane and caching it. Within the TTL the cached bundle is served; past it,
the bundle is re-fetched (hot-reload). If the control plane is unreachable, the
last-known-good bundle is served — never allow-all. With no cache at all, it fails
closed (`ConfigUnavailable`). A rejected/revoked credential (`IdentityUnresolved`)
is never served from cache, so a revoked agent stops working immediately.
"""

from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable

from common import ConfigBundle, ConfigUnavailable, IdentityUnresolved, now_epoch


@runtime_checkable
class ConfigFetcher(Protocol):
    def fetch(self, agent_id: str, credential: str) -> ConfigBundle: ...


class ConfigCache:
    def __init__(self, fetcher: ConfigFetcher, *, ttl_seconds: int = 30) -> None:
        self._fetcher = fetcher
        self._ttl = ttl_seconds
        self._entries: dict[str, tuple[int, ConfigBundle]] = {}
        self._lock = threading.Lock()

    def get(self, agent_id: str, credential: str) -> ConfigBundle:
        now = now_epoch()
        with self._lock:
            cached = self._entries.get(agent_id)
        if cached is not None and now - cached[0] < self._ttl:
            return cached[1]

        try:
            bundle = self._fetcher.fetch(agent_id, credential)
        except IdentityUnresolved:
            # Bad/revoked credential — never serve stale config for it.
            with self._lock:
                self._entries.pop(agent_id, None)
            raise
        except Exception as exc:
            if cached is not None:
                return cached[1]  # last-known-good; never allow-all
            raise ConfigUnavailable("control plane unreachable and no cached config") from exc

        with self._lock:
            self._entries[agent_id] = (now, bundle)
        return bundle

    def invalidate(self, agent_id: str) -> None:
        with self._lock:
            self._entries.pop(agent_id, None)
