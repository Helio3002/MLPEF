#!/usr/bin/env python3
"""Decision-path microbenchmark — measures the L1 + L2 hot path.

README constraint #3 sets the budget for the *decision path* (L1 Validate +
L2 Policy): **target < 10 ms p99**, achieved by keeping both layers in-process
and I/O-free (lexical path jailing, native ABAC eval, in-memory Ed25519 verify).
This script measures that path; it never asserts or fabricates a number. Run it
in your environment and paste the printed table into the README Benchmarks
section.

What is measured (and what is not):

  * Timed: a single call to ``layer1.validate(...)`` followed by
    ``layer2.evaluate(...)`` on an already-normalized ``Intent`` — i.e. exactly
    the work the proxy does between accepting a request and reaching L3.
  * NOT timed: ingress parsing, ``Intent`` construction, HITL-token *minting*
    (a control-plane op, off the hot path), config-bundle fetch, audit emit,
    or the sandbox (that is the separate L3 budget — see bench_sandbox.py).

Scenarios:

  * ``allow``       fs.read on a jailed path, no HITL — L1 ALLOW → L2 ALLOW
                    (cheapest full pass through both layers).
  * ``allow_hitl``  fs.write on a jailed path gated by an HITL rule, presenting
                    a valid pre-minted single-use token — L1 ALLOW → L2 verifies
                    the Ed25519 signature + consumes the nonce. This is the most
                    expensive decision path and the one that most needs to stay
                    under budget.

Usage::

    python tests/bench/bench_decision_path.py                 # default 20k iters
    python tests/bench/bench_decision_path.py --iters 50000
    python tests/bench/bench_decision_path.py --json           # machine-readable
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

# Make `common` (repo root) and the data-plane layer packages importable when this
# file is run directly as a script (sys.path[0] is tests/bench/, not the root).
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "data-plane"))

from common import (  # noqa: E402  (import after sys.path setup, by design)
    HITLRule,
    IngressSource,
    InMemoryNonceStore,
    Intent,
    PolicyProfile,
    ResourceKind,
    ResourceScope,
    Verdict,
    generate_keypair,
    mint_hitl_token,
)
from layer1_validation import validate  # noqa: E402
from layer2_policy import evaluate  # noqa: E402

# A fixed reference time keeps token expiry/verification deterministic across runs.
_NOW = 1_700_000_000

# The runner is given the iteration index so per-iteration state (a fresh,
# single-use HITL token) can be selected without timing its construction.
Runner = Callable[[int], None]
ScenarioFactory = Callable[[int], "Scenario"]


@dataclass
class Scenario:
    name: str
    layers: str  # human label of which layers the timed call exercises
    run: Runner


def _build_allow(_total: int) -> Scenario:
    """fs.read on a jailed path: L1 ALLOW → L2 ALLOW (no HITL, no token)."""
    _priv, pub = generate_keypair()
    nonce_store = InMemoryNonceStore()
    profile = PolicyProfile(
        profile_id="bench-allow",
        name="bench-allow",
        tenant="t",
        tool_allowlist=["fs.read"],
        resource_scopes=[ResourceScope(kind=ResourceKind.PATH, jail_prefix="/work")],
    )
    intent = Intent(
        intent_id="bench",
        agent_id="agent-1",
        tenant="t",
        tool="fs.read",
        action="fs.read",
        resource="/work/data.txt",
        arguments={"path": "/work/data.txt"},
        ingress=IngressSource.REST,
        received_at=1,
    )

    def run(_i: int) -> None:
        d1 = validate(intent, profile)
        if d1.verdict is not Verdict.ALLOW:
            raise RuntimeError(f"bench misconfigured: L1 denied ({d1.reason_code})")
        d2 = evaluate(intent, profile, public_key=pub, nonce_store=nonce_store, now=_NOW)
        if d2.verdict is not Verdict.ALLOW:
            raise RuntimeError(f"bench misconfigured: L2 denied ({d2.reason_code})")

    return Scenario("allow", "L1+L2", run)


def _build_allow_hitl(total: int) -> Scenario:
    """fs.write gated by an HITL rule, presenting a valid single-use token.

    Tokens are single-use, so we pre-mint one distinct token per iteration
    *outside* the timed loop — minting (Ed25519 sign) is a control-plane op and
    is deliberately excluded from the measurement. The timed call still performs
    the full Ed25519 *verify* + nonce consume.
    """
    priv, pub = generate_keypair()
    nonce_store = InMemoryNonceStore()
    profile = PolicyProfile(
        profile_id="bench-hitl",
        name="bench-hitl",
        tenant="t",
        tool_allowlist=["fs.write"],
        resource_scopes=[ResourceScope(kind=ResourceKind.PATH, jail_prefix="/work")],
        hitl_rules=[HITLRule(action_pattern="fs.write", resource_pattern="*")],
    )
    intents: list[Intent] = []
    for k in range(total):
        token = mint_hitl_token(
            priv,
            subject="agent-1",
            tenant="t",
            action="fs.write",
            resource="/work/data.txt",
            hitl_request_id="r",
            approver="admin",
            issued_at=_NOW,
            ttl_seconds=300,
            jti=f"bench-jti-{k}",  # unique → no false replay across iterations
        )
        intents.append(
            Intent(
                intent_id="bench",
                agent_id="agent-1",
                tenant="t",
                tool="fs.write",
                action="fs.write",
                resource="/work/data.txt",
                arguments={"path": "/work/data.txt", "content": "x"},
                ingress=IngressSource.REST,
                received_at=1,
                approval_token=token,
            )
        )

    def run(i: int) -> None:
        intent = intents[i]
        d1 = validate(intent, profile)
        if d1.verdict is not Verdict.ALLOW:
            raise RuntimeError(f"bench misconfigured: L1 denied ({d1.reason_code})")
        d2 = evaluate(intent, profile, public_key=pub, nonce_store=nonce_store, now=_NOW)
        if d2.verdict is not Verdict.ALLOW:
            raise RuntimeError(f"bench misconfigured: L2 denied ({d2.reason_code})")

    return Scenario("allow_hitl", "L1+L2 (Ed25519 verify)", run)


_SCENARIOS: dict[str, ScenarioFactory] = {
    "allow": _build_allow,
    "allow_hitl": _build_allow_hitl,
}


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
    layers: str
    count: int
    mean_ms: float
    min_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float


def _measure(scenario: Scenario, *, iters: int, warmup: int) -> Stats:
    run = scenario.run
    # Warm up: prime caches/branch predictors; these samples are discarded.
    for i in range(warmup):
        run(i)

    samples: list[float] = []
    base = warmup
    perf = time.perf_counter_ns
    for j in range(iters):
        start = perf()
        run(base + j)
        samples.append((perf() - start) / 1_000_000.0)  # ns → ms

    samples.sort()
    return Stats(
        name=scenario.name,
        layers=scenario.layers,
        count=len(samples),
        mean_ms=sum(samples) / len(samples),
        min_ms=samples[0],
        p50_ms=_percentile(samples, 50),
        p95_ms=_percentile(samples, 95),
        p99_ms=_percentile(samples, 99),
        max_ms=samples[-1],
    )


def _print_table(results: list[Stats], *, iters: int, warmup: int) -> None:
    print()
    print("MLPEF decision-path benchmark (L1 Validate + L2 Policy)")
    print(f"  iterations={iters}  warmup={warmup}  python={sys.version.split()[0]}")
    print("  budget: README constraint #3 → decision path target < 10 ms p99")
    print()
    header = f"{'scenario':<12} {'layers':<24} {'p50':>9} {'p95':>9} {'p99':>9} {'max':>9}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r.name:<12} {r.layers:<24} "
            f"{r.p50_ms:>8.4f}m {r.p95_ms:>8.4f}m {r.p99_ms:>8.4f}m {r.max_ms:>8.4f}m"
        )
    print()
    print("  (values in ms; 'm' suffix = milliseconds. Numbers are measured on")
    print("   this host — they are environment-dependent and never fabricated.)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MLPEF decision-path benchmark")
    parser.add_argument("--iters", type=int, default=20_000, help="timed iterations per scenario")
    parser.add_argument("--warmup", type=int, default=2_000, help="discarded warmup iterations")
    parser.add_argument(
        "--scenario",
        choices=[*_SCENARIOS, "all"],
        default="all",
        help="which scenario to run",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = parser.parse_args(argv)

    if args.iters <= 0 or args.warmup < 0:
        parser.error("--iters must be > 0 and --warmup must be >= 0")

    names = list(_SCENARIOS) if args.scenario == "all" else [args.scenario]
    total = args.iters + args.warmup
    results = [_measure(_SCENARIOS[name](total), iters=args.iters, warmup=args.warmup) for name in names]

    if args.json:
        print(json.dumps({"iters": args.iters, "warmup": args.warmup,
                          "results": [vars(r) for r in results]}, indent=2))
    else:
        _print_table(results, iters=args.iters, warmup=args.warmup)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
