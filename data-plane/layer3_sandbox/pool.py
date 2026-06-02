"""Warm-pool manager.

Keeps N pre-initialized, hardened sandboxes ready so checkout is fast (no
cold-start on the request path). A checked-out sandbox is used once and destroyed
by the caller (never reused); `refill` tops the pool back up. `last_checkout_ms`
records the most recent checkout latency for the benchmark numbers (Phase 11).
"""

from __future__ import annotations

import threading
from collections import deque

from common import SandboxLimits, monotonic_ms

from .backend import Sandbox, SandboxBackend


class WarmPool:
    def __init__(
        self,
        backend: SandboxBackend,
        *,
        image: str,
        limits: SandboxLimits,
        size: int,
    ) -> None:
        if size < 0:
            raise ValueError("pool size must be >= 0")
        self._backend = backend
        self._image = image
        self._limits = limits
        self._size = size
        self._idle: deque[Sandbox] = deque()
        self._lock = threading.Lock()
        self.last_checkout_ms = 0.0
        self._fill()

    def _fill(self) -> None:
        while len(self._idle) < self._size:
            self._idle.append(self._backend.create(self._limits, image=self._image))

    @property
    def idle_count(self) -> int:
        return len(self._idle)

    def checkout(self) -> Sandbox:
        start = monotonic_ms()
        with self._lock:
            # Fall back to a cold create only if the pool was exhausted.
            sandbox = self._idle.popleft() if self._idle else self._backend.create(
                self._limits, image=self._image
            )
        self.last_checkout_ms = monotonic_ms() - start
        return sandbox

    def refill(self) -> None:
        with self._lock:
            self._fill()

    def drain(self) -> None:
        with self._lock:
            while self._idle:
                self._idle.popleft().destroy()
