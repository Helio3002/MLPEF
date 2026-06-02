"""Layer 3 execution: run a tool's argv in a one-shot sandbox, fail-closed.

Checkout → run → (always) destroy + refill. A timeout, resource-limit kill,
egress block, or any sandbox error becomes a coded deny `LayerDecision` — an
ALLOW means only that the command executed *within the sandbox*; its exit code
and output are data passed on to Layer 4.
"""

from __future__ import annotations

from common import DenyReasonCode, LayerDecision, LayerName, MLPEFError

from .backend import SandboxResult
from .pool import WarmPool


def execute(
    pool: WarmPool, argv: list[str], *, timeout_seconds: int
) -> tuple[LayerDecision, SandboxResult | None]:
    try:
        sandbox = pool.checkout()
    except Exception:
        return (
            LayerDecision.deny(
                LayerName.L3_SANDBOX, DenyReasonCode.SANDBOX_FAILURE, "failed to acquire a sandbox"
            ),
            None,
        )

    try:
        try:
            result = sandbox.run(argv, timeout_seconds=timeout_seconds)
        except MLPEFError as exc:
            # Typed sandbox errors carry their own reason code (timeout, resource
            # limit, egress block, ...).
            return LayerDecision.from_error(exc), None
        except Exception:
            return (
                LayerDecision.deny(
                    LayerName.L3_SANDBOX,
                    DenyReasonCode.SANDBOX_FAILURE,
                    "sandbox execution failed",
                ),
                None,
            )

        if result.timed_out:
            return (
                LayerDecision.deny(
                    LayerName.L3_SANDBOX,
                    DenyReasonCode.SANDBOX_TIMEOUT,
                    "sandbox execution timed out",
                    elapsed_ms=result.elapsed_ms,
                ),
                result,
            )
        return (
            LayerDecision.allow(
                LayerName.L3_SANDBOX,
                elapsed_ms=result.elapsed_ms,
                metadata={"exit_code": result.exit_code},
            ),
            result,
        )
    finally:
        # One-shot: the sandbox is always destroyed (never reused), then refilled.
        sandbox.destroy()
        pool.refill()
