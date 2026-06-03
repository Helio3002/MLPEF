"""End-to-end pipeline + proxy tests (fakes only — no Docker / control plane)."""

from __future__ import annotations

from common import (
    DenyReasonCode,
    HITLRule,
    IdentityUnresolved,
    IngressSource,
    InMemoryNonceStore,
    Intent,
    PolicyProfile,
    ResourceKind,
    ResourceScope,
    SandboxLimits,
    Verdict,
    generate_keypair,
)
from layer3_sandbox import WarmPool
from layer3_sandbox.backend import SandboxResult
from layer5_audit import Auditor, InMemoryAuditSink
from proxy import ConfigCache, Pipeline, Proxy


class FakeSandbox:
    def __init__(self, sid: str, result: SandboxResult) -> None:
        self.id = sid
        self._result = result
        self.destroyed = False

    def run(self, argv: list[str], *, timeout_seconds: int) -> SandboxResult:
        return self._result

    def destroy(self) -> None:
        self.destroyed = True


class FakeBackend:
    def __init__(self, result: SandboxResult) -> None:
        self._result = result
        self.created: list[FakeSandbox] = []

    def create(self, limits: SandboxLimits, *, image: str) -> FakeSandbox:
        sandbox = FakeSandbox(f"sb-{len(self.created) + 1}", self._result)
        self.created.append(sandbox)
        return sandbox


def _make_pipeline(
    *, stdout: str = "output", timed_out: bool = False
) -> tuple[Pipeline, InMemoryAuditSink]:
    sink = InMemoryAuditSink()
    result = SandboxResult(
        exit_code=0, stdout=stdout, stderr="", timed_out=timed_out, elapsed_ms=1.0
    )
    pool = WarmPool(FakeBackend(result), image="img", limits=SandboxLimits(), size=1)
    pipeline = Pipeline(
        public_key=generate_keypair()[1],
        nonce_store=InMemoryNonceStore(),
        sandbox_pool=pool,
        auditor=Auditor(sink),
    )
    return pipeline, sink


def _intent(tool: str, arguments: dict[str, object]) -> Intent:
    return Intent(
        intent_id="i",
        agent_id="a",
        tenant="t",
        tool=tool,
        action=tool,
        resource="-",
        ingress=IngressSource.REST,
        received_at=1,
        arguments=arguments,
    )


def _profile(allowlist: list[str], hitl: list[HITLRule] | None = None) -> PolicyProfile:
    return PolicyProfile(
        profile_id="p", name="p", tenant="t", tool_allowlist=allowlist, hitl_rules=hitl or []
    )


def test_allow_flow_executes_filters_and_audits() -> None:
    pipeline, sink = _make_pipeline(stdout="hello world")
    intent = _intent("shell.exec", {"argv": ["echo", "hello"]})
    outcome = pipeline.process(intent, _profile(["shell.exec"]))
    assert outcome.result.allowed
    assert outcome.output == "hello world"
    assert len(sink.events) == 1
    assert sink.events[0].final_verdict is Verdict.ALLOW


def test_l1_traversal_is_denied_and_audited() -> None:
    pipeline, sink = _make_pipeline()
    profile = PolicyProfile(
        profile_id="p", name="p", tenant="t", tool_allowlist=["fs.read"],
        resource_scopes=[ResourceScope(kind=ResourceKind.PATH, jail_prefix="/work")],
    )
    outcome = pipeline.process(_intent("fs.read", {"path": "../../etc/passwd"}), profile)
    assert outcome.result.final_verdict is Verdict.DENY
    assert outcome.result.reason_code is DenyReasonCode.PATH_TRAVERSAL
    assert outcome.output == ""
    assert len(sink.events) == 1  # denials are audited too


def test_hitl_required_stops_before_execution() -> None:
    pipeline, sink = _make_pipeline()
    profile = _profile(["shell.exec"], hitl=[HITLRule(action_pattern="shell.exec")])
    outcome = pipeline.process(_intent("shell.exec", {"argv": ["echo", "x"]}), profile)
    assert outcome.result.final_verdict is Verdict.HITL_REQUIRED
    assert outcome.output == ""
    assert len(sink.events) == 1


def test_l3_timeout_is_denied() -> None:
    pipeline, _ = _make_pipeline(timed_out=True)
    intent = _intent("shell.exec", {"argv": ["echo", "x"]})
    outcome = pipeline.process(intent, _profile(["shell.exec"]))
    assert outcome.result.final_verdict is Verdict.DENY
    assert outcome.result.reason_code is DenyReasonCode.SANDBOX_TIMEOUT


class _FailingSink:
    def emit(self, event: object) -> None:
        raise RuntimeError("audit store down")


def test_audit_failure_fails_closed() -> None:
    result = SandboxResult(exit_code=0, stdout="ok", stderr="", timed_out=False, elapsed_ms=1.0)
    pool = WarmPool(FakeBackend(result), image="img", limits=SandboxLimits(), size=1)
    pipeline = Pipeline(
        public_key=generate_keypair()[1],
        nonce_store=InMemoryNonceStore(),
        sandbox_pool=pool,
        auditor=Auditor(_FailingSink()),
    )
    intent = _intent("shell.exec", {"argv": ["echo", "x"]})
    outcome = pipeline.process(intent, _profile(["shell.exec"]))
    assert outcome.result.final_verdict is Verdict.DENY
    assert outcome.result.reason_code is DenyReasonCode.AUDIT_FAILURE
    assert outcome.output == ""


class _RejectingFetcher:
    def fetch(self, agent_id: str, credential: str) -> object:
        raise IdentityUnresolved("bad credential")


def test_proxy_identity_failure_is_denied_and_audited() -> None:
    pipeline, sink = _make_pipeline()
    proxy = Proxy(config_cache=ConfigCache(_RejectingFetcher(), ttl_seconds=30), pipeline=pipeline)
    outcome = proxy.handle(_intent("shell.exec", {"argv": ["echo", "x"]}), credential="bad")
    assert outcome.result.final_verdict is Verdict.DENY
    assert outcome.result.reason_code is DenyReasonCode.IDENTITY_UNRESOLVED
    assert len(sink.events) == 1  # identity failure is audited
