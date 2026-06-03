"""ConfigCache: TTL, last-known-good, and fail-closed behavior."""

from __future__ import annotations

import pytest
from common import ConfigBundle, ConfigUnavailable, IdentityUnresolved, default_locked_down_profile

from proxy import ConfigCache


def _bundle(etag: str = "v1") -> ConfigBundle:
    return ConfigBundle(
        agent_id="a", profile=default_locked_down_profile("t"), issued_at=0, etag=etag
    )


class FakeFetcher:
    def __init__(
        self, *, bundle: ConfigBundle | None = None, error: Exception | None = None
    ) -> None:
        self.calls = 0
        self._bundle = bundle
        self._error = error

    def fetch(self, agent_id: str, credential: str) -> ConfigBundle:
        self.calls += 1
        if self._error is not None:
            raise self._error
        assert self._bundle is not None
        return self._bundle


def test_cache_hit_within_ttl() -> None:
    fetcher = FakeFetcher(bundle=_bundle())
    cache = ConfigCache(fetcher, ttl_seconds=300)
    first = cache.get("a", "key")
    second = cache.get("a", "key")
    assert fetcher.calls == 1  # second served from cache
    assert first is second


def test_ttl_zero_always_refetches() -> None:
    fetcher = FakeFetcher(bundle=_bundle())
    cache = ConfigCache(fetcher, ttl_seconds=0)
    cache.get("a", "key")
    cache.get("a", "key")
    assert fetcher.calls == 2


def test_last_known_good_on_transient_failure() -> None:
    good = _bundle()
    fetcher = FakeFetcher(bundle=good)
    cache = ConfigCache(fetcher, ttl_seconds=0)
    cache.get("a", "key")  # populate the cache
    fetcher._error = RuntimeError("control plane down")
    assert cache.get("a", "key") is good  # served stale; never allow-all


def test_no_cache_and_failure_is_config_unavailable() -> None:
    cache = ConfigCache(FakeFetcher(error=RuntimeError("down")), ttl_seconds=30)
    with pytest.raises(ConfigUnavailable):
        cache.get("a", "key")


def test_identity_unresolved_is_not_served_from_cache() -> None:
    fetcher = FakeFetcher(bundle=_bundle())
    cache = ConfigCache(fetcher, ttl_seconds=0)
    cache.get("a", "key")  # populate the cache
    fetcher._error = IdentityUnresolved("revoked")
    with pytest.raises(IdentityUnresolved):
        cache.get("a", "key")  # revoked credential -> never stale
