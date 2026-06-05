#!/usr/bin/env python3
"""Sandbox-checkout microbenchmark — measures the L3 warm-pool budget.

README constraint #3 keeps the sandbox on a *separate* budget from the decision
path: **warm-pool checkout target < 50 ms**, and it states plainly that Docker
cold-start is hundreds of ms — which is exactly why we pre-warm. This script
measures both halves so the contrast is explicit and honest:

  * ``checkout``  pop a ready, pre-warmed sandbox off the pool — the latency a
                  request actually pays. This is what the < 50 ms budget covers.
  * ``cold``      ``backend.create(...)`` — spin up one hardened container from
                  scratch. This is the cost the warm pool hides off the request
                  path; we measure it only to justify pre-warming, never to
                  claim it as the request-path number.

It requires a reachable Docker daemon and a local image (default ``alpine``).
**Without Docker it skips cleanly (exit 0)** rather than failing — the charter
forbids fabricated benchmarks, and a sandbox number with no sandbox would be
exactly that.

Usage::

    python tests/bench/bench_sandbox.py                  # default 20 sandboxes
    python tests/bench/bench_sandbox.py --iters 40 --image alpine:3.20
    python tests/bench/bench_sandbox.py --json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from dataclasses import dataclass
from typing import Any

# Make `common` (repo root) and the data-plane layer packages importable when run
# directly as a script (sys.path[0] is tests/bench/, not the repo root).
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "data-plane"))

from common import SandboxLimits  # noqa: E402  (import after sys.path setup, by design)
from layer3_sandbox import DockerSandboxBackend, WarmPool  # noqa: E402
from layer3_sandbox.backend import Sandbox  # noqa: E402


def _connect_docker() -> tuple[Any | None, str | None]:
    """Return (client, None) if Docker is usable, else (None, reason-to-skip)."""
    try:
        import docker
    except ImportError:
        return None, "docker SDK not installed — `pip install -e '.[proxy]'`"
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # daemon down / no socket / permission
        return None, f"docker daemon not reachable: {exc}"
    return client, None


def _ensure_image(client: Any, image: str) -> str | None:
    """Ensure `image` is present locally; pull if missing. Returns a skip reason on failure."""
    try:
        client.images.get(image)
        return None
    except Exception:
        pass
    print(f"  image {image!r} not present locally — pulling once (untimed)...")
    try:
        client.images.pull(image)
    except Exception as exc:
        return f"could not pull image {image!r}: {exc}"
    return None


def _percentile(sorted_samples: list[float], pct: float) -> float:
    """Linear-interpolation percentile over an already-sorted sample list."""
    if not sorted_samples:
        return float("nan")
    if len(sorted_samples) == 1:
        return sorted_samples[0]
    rank = (len(sorted_samples) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(sorted_samples) - 1)
    frac = rank - low
    return sorted_samples[low] * (1.0 - frac) + sorted_samples[high] * frac


@dataclass
class Stats:
    name: str
    count: int
    mean_ms: float
    min_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float


def _stats(name: str, samples: list[float]) -> Stats:
    samples.sort()
    return Stats(
        name=name,
        count=len(samples),
        mean_ms=sum(samples) / len(samples),
        min_ms=samples[0],
        p50_ms=_percentile(samples, 50),
        p95_ms=_percentile(samples, 95),
        p99_ms=_percentile(samples, 99),
        max_ms=samples[-1],
    )


def _measure_cold(backend: DockerSandboxBackend, *, image: str, limits: SandboxLimits,
                  iters: int) -> Stats:
    """Time `backend.create(...)` (full container start), destroying each immediately."""
    perf = time.perf_counter_ns
    samples: list[float] = []
    for _ in range(iters):
        start = perf()
        sandbox = backend.create(limits, image=image)
        samples.append((perf() - start) / 1_000_000.0)
        sandbox.destroy()
    return _stats("cold_create", samples)


def _measure_checkout(backend: DockerSandboxBackend, *, image: str, limits: SandboxLimits,
                      iters: int) -> Stats:
    """Pre-warm a pool of `iters` sandboxes, then time popping each one off."""
    pool = WarmPool(backend, image=image, limits=limits, size=iters)
    checked_out: list[Sandbox] = []
    perf = time.perf_counter_ns
    samples: list[float] = []
    try:
        for _ in range(iters):
            start = perf()
            sandbox = pool.checkout()  # warm path: deque popleft, no container start
            samples.append((perf() - start) / 1_000_000.0)
            checked_out.append(sandbox)
    finally:
        # One-shot model: every checked-out sandbox is destroyed, never reused.
        for sandbox in checked_out:
            sandbox.destroy()
        pool.drain()
    return _stats("warm_checkout", samples)


def _print_table(results: list[Stats], *, iters: int, image: str) -> None:
    print()
    print("MLPEF sandbox benchmark (L3 warm pool)")
    print(f"  sandboxes={iters}  image={image}  python={sys.version.split()[0]}")
    print("  budget: README constraint #3 → warm-pool checkout target < 50 ms")
    print("          (cold_create is the off-request-path cost the pool hides)")
    print()
    header = f"{'phase':<16} {'count':>6} {'p50':>10} {'p95':>10} {'p99':>10} {'max':>10}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.name:<16} {r.count:>6} "
            f"{r.p50_ms:>9.3f}m {r.p95_ms:>9.3f}m {r.p99_ms:>9.3f}m {r.max_ms:>9.3f}m"
        )
    print()
    print("  (values in ms; measured on this host. Cold-start is environment- and")
    print("   image-dependent; numbers are never fabricated.)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MLPEF sandbox warm-pool benchmark")
    parser.add_argument("--iters", type=int, default=20, help="sandboxes to create/checkout")
    parser.add_argument("--image", default="alpine", help="container image for the sandbox")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args(argv)

    if args.iters <= 0:
        parser.error("--iters must be > 0")

    client, skip_reason = _connect_docker()
    if client is None:
        # Skip cleanly — a fabricated sandbox number is worse than no number.
        print(f"SKIP bench_sandbox: {skip_reason}", file=sys.stderr)
        return 0

    skip_reason = _ensure_image(client, args.image)
    if skip_reason is not None:
        print(f"SKIP bench_sandbox: {skip_reason}", file=sys.stderr)
        return 0

    backend = DockerSandboxBackend(idle_seconds=60, client=client)
    limits = SandboxLimits()  # safe-floor hardening (read-only, caps dropped, no net)

    results = [
        _measure_cold(backend, image=args.image, limits=limits, iters=args.iters),
        _measure_checkout(backend, image=args.image, limits=limits, iters=args.iters),
    ]

    if args.json:
        print(json.dumps(
            {"iters": args.iters, "image": args.image, "results": [vars(r) for r in results]},
            indent=2,
        ))
    else:
        _print_table(results, iters=args.iters, image=args.image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
