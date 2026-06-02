"""Unit tests for the HITL signed-token library (happy path + per-field guards)."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common import (
    InMemoryNonceStore,
    TokenExpired,
    TokenInvalidSignature,
    TokenMalformed,
    TokenNotYetValid,
    TokenScopeMismatch,
    mint_hitl_token,
    verify_hitl_token,
)

Keypair = tuple[Ed25519PrivateKey, Ed25519PublicKey]

_DEFAULTS = {
    "subject": "agent-1",
    "tenant": "tenant-a",
    "action": "fs.delete",
    "resource": "/data/report.csv",
    "hitl_request_id": "req-123",
    "approver": "admin-1",
}


def _mint(priv: Ed25519PrivateKey, now: int, *, ttl_seconds: int = 300, **overrides: str) -> str:
    params = {**_DEFAULTS, **overrides}
    return mint_hitl_token(
        priv,
        subject=params["subject"],
        tenant=params["tenant"],
        action=params["action"],
        resource=params["resource"],
        hitl_request_id=params["hitl_request_id"],
        approver=params["approver"],
        issued_at=now,
        ttl_seconds=ttl_seconds,
    )


def _verify(
    token: str,
    pub: Ed25519PublicKey,
    now: int,
    nonce_store: InMemoryNonceStore,
    **overrides: str,
) -> object:
    params = {**_DEFAULTS, **overrides}
    return verify_hitl_token(
        token,
        pub,
        expected_subject=params["subject"],
        expected_tenant=params["tenant"],
        expected_action=params["action"],
        expected_resource=params["resource"],
        now=now,
        nonce_store=nonce_store,
    )


def test_mint_and_verify_round_trip(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    priv, pub = keypair
    token = _mint(priv, now)
    claims = verify_hitl_token(
        token,
        pub,
        expected_subject="agent-1",
        expected_tenant="tenant-a",
        expected_action="fs.delete",
        expected_resource="/data/report.csv",
        now=now,
        nonce_store=nonce_store,
    )
    assert claims.subject == "agent-1"
    assert claims.action == "fs.delete"
    assert claims.expires_at == now + 300
    assert claims.jti  # a nonce was generated


def test_expired_token_is_rejected(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    priv, pub = keypair
    token = _mint(priv, now, ttl_seconds=10)
    with pytest.raises(TokenExpired):
        _verify(token, pub, now + 11, nonce_store)


def test_not_yet_valid_token_is_rejected(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    priv, pub = keypair
    token = _mint(priv, now + 1000)
    with pytest.raises(TokenNotYetValid):
        _verify(token, pub, now, nonce_store)


@pytest.mark.parametrize("field", ["subject", "tenant", "action", "resource"])
def test_scope_mismatch_on_each_bound_field(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int, field: str
) -> None:
    priv, pub = keypair
    token = _mint(priv, now)
    with pytest.raises(TokenScopeMismatch):
        _verify(token, pub, now, nonce_store, **{field: "something-else"})


def test_tampering_a_claim_breaks_the_signature(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    # Mint a read token, then try to escalate it to delete by editing the
    # payload while keeping the original signature. Must fail signature check.
    priv, pub = keypair
    token = _mint(priv, now, action="fs.read")
    payload_seg, sig_seg = token.split(".")
    raw = base64.urlsafe_b64decode(payload_seg + "=" * (-len(payload_seg) % 4))
    data = json.loads(raw)
    data["action"] = "fs.delete"
    forged_payload = (
        base64.urlsafe_b64encode(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    forged = f"{forged_payload}.{sig_seg}"
    # The signature no longer matches the (tampered) payload bytes.
    with pytest.raises(TokenInvalidSignature):
        _verify(forged, pub, now, nonce_store, action="fs.delete")


@pytest.mark.parametrize("bad", ["", "no-dot", "a.b.c", ".", "onlyleft.", ".onlyright"])
def test_malformed_tokens_are_rejected(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int, bad: str
) -> None:
    _, pub = keypair
    with pytest.raises(TokenMalformed):
        _verify(bad, pub, now, nonce_store)
