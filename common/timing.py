"""Timing utilities for the latency budget.

These are *observability only* — timings never feed a security decision, so they
do not violate the deterministic-core rule. The decision path (L1 + L2) targets
< 10 ms p99; the execution path (L3 sandbox checkout) has its own budget. We
measure with a monotonic clock and record real numbers; we never fabricate them.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import TracebackType


def now_epoch() -> int:
    """Wall-clock UNIX seconds. Used for token expiry and audit timestamps.

    This is the *only* sanctioned clock read in the decision path, and only for
    token expiry comparison — never for control-flow branching beyond that.
    """
    return int(time.time())


def monotonic_ms() -> float:
    """Monotonic milliseconds for measuring elapsed durations."""
    return time.perf_counter_ns() / 1_000_000.0


@dataclass
class Stopwatch:
    """Context manager that records elapsed wall time in milliseconds.

    Example:
        with Stopwatch() as sw:
            do_work()
        record(sw.elapsed_ms)
    """

    elapsed_ms: float = 0.0
    _start_ns: int = field(default=0, repr=False)

    def __enter__(self) -> Stopwatch:
        self._start_ns = time.perf_counter_ns()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.elapsed_ms = (time.perf_counter_ns() - self._start_ns) / 1_000_000.0


@dataclass
class PhaseTimings:
    """Accumulates per-phase elapsed times for a single request lifecycle."""

    phases: dict[str, float] = field(default_factory=dict)

    @contextmanager
    def measure(self, phase: str) -> Iterator[None]:
        start = time.perf_counter_ns()
        try:
            yield
        finally:
            self.phases[phase] = (time.perf_counter_ns() - start) / 1_000_000.0

    @property
    def total_ms(self) -> float:
        return sum(self.phases.values())
