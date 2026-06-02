"""Layer 2 orchestration: classify via the policy engine, then enforce HITL.

If the action classifies as HITL_REQUIRED, a scoped / single-use / expiring
approval token must be present and verify (signature + subject + tenant + action
+ resource + expiry + nonce). A validly-signed token used out of scope, replayed,
or expired is a coded deny — and a security event for scope/replay/forgery.
Everything is fail-closed: any error becomes a deny `LayerDecision`.
"""

from __future__ import annotations

from common import (
    DenyReasonCode,
    Intent,
    LayerDecision,
    LayerName,
    MLPEFError,
    NonceStore,
    PolicyProfile,
    Stopwatch,
    Verdict,
    verify_hitl_token,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .engine import NativePolicyEngine, PolicyEngine

_DEFAULT_ENGINE: PolicyEngine = NativePolicyEngine()


def _decide(
    intent: Intent,
    profile: PolicyProfile,
    *,
    public_key: Ed25519PublicKey,
    nonce_store: NonceStore,
    now: int,
    engine: PolicyEngine,
    leeway_seconds: int,
) -> LayerDecision:
    verdict = engine.classify(intent, profile)

    if verdict is Verdict.DENY:
        return LayerDecision.deny(
            LayerName.L2_POLICY,
            DenyReasonCode.POLICY_DEFAULT_DENY,
            "no allow rule matched (default deny)",
        )
    if verdict is Verdict.ALLOW:
        return LayerDecision.allow(LayerName.L2_POLICY)

    # HITL_REQUIRED
    if intent.approval_token is None:
        return LayerDecision.hitl_required(
            LayerName.L2_POLICY, "human approval required for this action"
        )
    try:
        claims = verify_hitl_token(
            intent.approval_token,
            public_key,
            expected_subject=intent.agent_id,
            expected_tenant=intent.tenant,
            expected_action=intent.action,
            expected_resource=intent.resource,
            now=now,
            nonce_store=nonce_store,
            leeway_seconds=leeway_seconds,
        )
    except MLPEFError as exc:
        return LayerDecision.from_error(exc)
    return LayerDecision.allow(
        LayerName.L2_POLICY,
        reason="approved via HITL token",
        metadata={"hitl_request_id": claims.hitl_request_id, "approver": claims.approver},
    )


def evaluate(
    intent: Intent,
    profile: PolicyProfile,
    *,
    public_key: Ed25519PublicKey,
    nonce_store: NonceStore,
    now: int,
    engine: PolicyEngine | None = None,
    leeway_seconds: int = 0,
) -> LayerDecision:
    active = engine if engine is not None else _DEFAULT_ENGINE
    with Stopwatch() as stopwatch:
        decision = _decide(
            intent,
            profile,
            public_key=public_key,
            nonce_store=nonce_store,
            now=now,
            engine=active,
            leeway_seconds=leeway_seconds,
        )
    return decision.model_copy(update={"elapsed_ms": stopwatch.elapsed_ms})
