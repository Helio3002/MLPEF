"""Layer 2 policy + HITL-token enforcement tests."""

from __future__ import annotations

from collections.abc import Iterable

from common import (
    DenyReasonCode,
    HITLRule,
    IngressSource,
    InMemoryNonceStore,
    Intent,
    PolicyProfile,
    Verdict,
    generate_keypair,
    mint_hitl_token,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from layer2_policy import evaluate

NOW = 1_700_000_000


def _profile(allowlist: Iterable[str], hitl: Iterable[HITLRule] = ()) -> PolicyProfile:
    return PolicyProfile(
        profile_id="p",
        name="p",
        tenant="t",
        tool_allowlist=list(allowlist),
        hitl_rules=list(hitl),
    )


def _intent(tool: str, action: str, resource: str, *, token: str | None = None) -> Intent:
    return Intent(
        intent_id="i",
        agent_id="agent-1",
        tenant="t",
        tool=tool,
        action=action,
        resource=resource,
        ingress=IngressSource.REST,
        received_at=1,
        approval_token=token,
    )


def _mint(
    priv: Ed25519PrivateKey,
    *,
    action: str = "fs.delete",
    resource: str = "/work/x",
    ttl_seconds: int = 300,
    issued_at: int = NOW,
) -> str:
    return mint_hitl_token(
        priv,
        subject="agent-1",
        tenant="t",
        action=action,
        resource=resource,
        hitl_request_id="r1",
        approver="admin-1",
        issued_at=issued_at,
        ttl_seconds=ttl_seconds,
    )


def test_default_deny_when_tool_not_allowed() -> None:
    _, pub = generate_keypair()
    decision = evaluate(
        _intent("fs.delete", "fs.delete", "/work/x"),
        _profile([]),
        public_key=pub,
        nonce_store=InMemoryNonceStore(),
        now=NOW,
    )
    assert decision.verdict is Verdict.DENY
    assert decision.reason_code is DenyReasonCode.POLICY_DEFAULT_DENY


def test_allows_permitted_non_destructive() -> None:
    _, pub = generate_keypair()
    decision = evaluate(
        _intent("fs.read", "fs.read", "/work/x"),
        _profile(["fs.read"]),
        public_key=pub,
        nonce_store=InMemoryNonceStore(),
        now=NOW,
    )
    assert decision.verdict is Verdict.ALLOW


def test_hitl_required_without_token() -> None:
    _, pub = generate_keypair()
    profile = _profile(["fs.delete"], hitl=[HITLRule(action_pattern="fs.delete")])
    decision = evaluate(
        _intent("fs.delete", "fs.delete", "/work/x"),
        profile,
        public_key=pub,
        nonce_store=InMemoryNonceStore(),
        now=NOW,
    )
    assert decision.verdict is Verdict.HITL_REQUIRED
    assert decision.reason_code is DenyReasonCode.HITL_REQUIRED


def test_allows_with_valid_token() -> None:
    priv, pub = generate_keypair()
    profile = _profile(["fs.delete"], hitl=[HITLRule(action_pattern="fs.delete")])
    token = _mint(priv)
    decision = evaluate(
        _intent("fs.delete", "fs.delete", "/work/x", token=token),
        profile,
        public_key=pub,
        nonce_store=InMemoryNonceStore(),
        now=NOW,
    )
    assert decision.verdict is Verdict.ALLOW
    assert decision.metadata["hitl_request_id"] == "r1"


def test_replayed_token_is_denied() -> None:
    priv, pub = generate_keypair()
    profile = _profile(["fs.delete"], hitl=[HITLRule(action_pattern="fs.delete")])
    store = InMemoryNonceStore()
    token = _mint(priv)
    intent = _intent("fs.delete", "fs.delete", "/work/x", token=token)

    first = evaluate(intent, profile, public_key=pub, nonce_store=store, now=NOW)
    assert first.verdict is Verdict.ALLOW
    replay = evaluate(intent, profile, public_key=pub, nonce_store=store, now=NOW)
    assert replay.verdict is Verdict.DENY
    assert replay.reason_code is DenyReasonCode.TOKEN_REPLAY
    assert replay.security_event is True


def test_scope_mismatched_token_is_denied() -> None:
    priv, pub = generate_keypair()
    profile = _profile(["fs.delete"], hitl=[HITLRule(action_pattern="fs.delete")])
    token = _mint(priv, resource="/work/other")  # approved for a different resource
    decision = evaluate(
        _intent("fs.delete", "fs.delete", "/work/x", token=token),
        profile,
        public_key=pub,
        nonce_store=InMemoryNonceStore(),
        now=NOW,
    )
    assert decision.reason_code is DenyReasonCode.TOKEN_SCOPE_MISMATCH
    assert decision.security_event is True


def test_expired_token_is_denied() -> None:
    priv, pub = generate_keypair()
    profile = _profile(["fs.delete"], hitl=[HITLRule(action_pattern="fs.delete")])
    token = _mint(priv, ttl_seconds=10, issued_at=NOW - 1000)
    decision = evaluate(
        _intent("fs.delete", "fs.delete", "/work/x", token=token),
        profile,
        public_key=pub,
        nonce_store=InMemoryNonceStore(),
        now=NOW,
    )
    assert decision.reason_code is DenyReasonCode.TOKEN_EXPIRED
