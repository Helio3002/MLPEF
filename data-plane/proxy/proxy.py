"""Proxy entry point: resolve identity/config, then run the pipeline.

Identity resolution is the config-bundle pull (a valid credential yields the
agent's profile). If it fails — bad/revoked credential (IdentityUnresolved) or
control plane unreachable with no cache (ConfigUnavailable) — the request is
denied and audited; it never proceeds to the layers (fail-closed).
"""

from __future__ import annotations

from common import Intent, LayerDecision, MLPEFError

from .config_cache import ConfigCache
from .pipeline import Pipeline, PipelineOutcome


class Proxy:
    def __init__(self, *, config_cache: ConfigCache, pipeline: Pipeline) -> None:
        self._cache = config_cache
        self._pipeline = pipeline

    def handle(self, intent: Intent, *, credential: str) -> PipelineOutcome:
        try:
            bundle = self._cache.get(intent.agent_id, credential)
        except MLPEFError as exc:
            return self._pipeline.deny_and_audit(intent, LayerDecision.from_error(exc))
        return self._pipeline.process(intent, bundle.profile)
