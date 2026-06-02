"""Warm-pool + executor behavior, using a fake backend (no Docker)."""

from __future__ import annotations

from common import DenyReasonCode, SandboxLimits, Verdict
from common.errors import ResourceLimitExceeded
from layer3_sandbox import WarmPool, execute
from layer3_sandbox.backend import SandboxResult

_OK = SandboxResult(exit_code=0, stdout="ok", stderr="", timed_out=False, elapsed_ms=1.0)


class FakeSandbox:
    def __init__(self, sid: str, *, result: SandboxResult | None, error: Exception | None) -> None:
        self.id = sid
        self._result = result
        self._error = error
        self.destroyed = False

    def run(self, argv: list[str], *, timeout_seconds: int) -> SandboxResult:
        if self._error is not None:
            raise self._error
        assert self._result is not None
        return self._result

    def destroy(self) -> None:
        self.destroyed = True


class FakeBackend:
    def __init__(
        self, *, result: SandboxResult | None = None, error: Exception | None = None
    ) -> None:
        self.created: list[FakeSandbox] = []
        self._result = result
        self._error = error

    def create(self, limits: SandboxLimits, *, image: str) -> FakeSandbox:
        sandbox = FakeSandbox(f"sb-{len(self.created) + 1}", result=self._result, error=self._error)
        self.created.append(sandbox)
        return sandbox


def _pool(backend: FakeBackend, size: int = 2) -> WarmPool:
    return WarmPool(backend, image="img", limits=SandboxLimits(), size=size)


def test_pool_prewarms_and_refills() -> None:
    backend = FakeBackend(result=_OK)
    pool = _pool(backend, size=2)
    assert pool.idle_count == 2
    pool.checkout()
    assert pool.idle_count == 1
    pool.refill()
    assert pool.idle_count == 2
    assert len(backend.created) == 3  # 2 prewarmed + 1 refill


def test_execute_success_and_destroys_sandbox() -> None:
    backend = FakeBackend(result=_OK)
    pool = _pool(backend, size=1)
    decision, result = execute(pool, ["echo", "hi"], timeout_seconds=5)
    assert decision.verdict is Verdict.ALLOW
    assert result is not None and result.exit_code == 0
    assert backend.created[0].destroyed is True  # one-shot: never reused


def test_execute_timeout_denies() -> None:
    timed = SandboxResult(exit_code=-1, stdout="", stderr="", timed_out=True, elapsed_ms=5000.0)
    decision, _ = execute(
        _pool(FakeBackend(result=timed), size=1), ["sleep", "99"], timeout_seconds=1
    )
    assert decision.verdict is Verdict.DENY
    assert decision.reason_code is DenyReasonCode.SANDBOX_TIMEOUT


def test_execute_resource_limit_denies() -> None:
    backend = FakeBackend(error=ResourceLimitExceeded("oom"))
    decision, _ = execute(_pool(backend, size=1), ["x"], timeout_seconds=1)
    assert decision.reason_code is DenyReasonCode.RESOURCE_LIMIT


def test_execute_unexpected_error_fails_closed() -> None:
    backend = FakeBackend(error=RuntimeError("docker boom"))
    pool = _pool(backend, size=1)
    decision, _ = execute(pool, ["x"], timeout_seconds=1)
    assert decision.verdict is Verdict.DENY
    assert decision.reason_code is DenyReasonCode.SANDBOX_FAILURE
    assert backend.created[0].destroyed is True  # cleaned up even on failure
