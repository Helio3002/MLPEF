"""Adversarial tests for the HITL approval token.

These map directly to named threats in THREAT_MODEL.md:
  * HITL-token replay              -> test_replay_is_blocked
  * Confused Deputy / token misuse -> test_scope_mismatch_*
  * Forgery under Assume-Breach    -> test_cross_key_forgery_is_rejected
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common import (
    InMemoryNonceStore,
    TokenInvalidSignature,
    TokenReplay,
    TokenScopeMismatch,
    generate_keypair,
    mint_hitl_token,
    verify_hitl_token,
)

Keypair = tuple[Ed25519PrivateKey, Ed25519PublicKey]


def _mint_delete_token(priv: Ed25519PrivateKey, now: int) -> str:
    return mint_hitl_token(
        priv,
        subject="agent-1",
        tenant="tenant-a",
        action="fs.delete",
        resource="/data/report.csv",
        hitl_request_id="req-123",
        approver="admin-1",
        issued_at=now,
        ttl_seconds=300,
    )


def _verify_delete(
    token: str, pub: Ed25519PublicKey, now: int, store: InMemoryNonceStore
) -> object:
    return verify_hitl_token(
        token,
        pub,
        expected_subject="agent-1",
        expected_tenant="tenant-a",
        expected_action="fs.delete",
        expected_resource="/data/report.csv",
        now=now,
        nonce_store=store,
    )


def test_replay_is_blocked(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    priv, pub = keypair
    token = _mint_delete_token(priv, now)

    # First use succeeds and consumes the single-use nonce.
    _verify_delete(token, pub, now, nonce_store)

    # Replaying the identical token is denied.
    with pytest.raises(TokenReplay):
        _verify_delete(token, pub, now, nonce_store)


def test_scope_mismatch_is_a_security_event_and_does_not_burn_the_nonce(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    """A token approved for fs.delete must not authorize fs.read, and a failed
    mismatch attempt must NOT consume the nonce — the legitimate fs.delete use
    has to still succeed afterward."""
    priv, pub = keypair
    token = _mint_delete_token(priv, now)

    # Attacker tries to use the delete-approval for a different action.
    with pytest.raises(TokenScopeMismatch) as exc_info:
        verify_hitl_token(
            token,
            pub,
            expected_subject="agent-1",
            expected_tenant="tenant-a",
            expected_action="fs.read",  # not what was approved
            expected_resource="/data/report.csv",
            now=now,
            nonce_store=nonce_store,
        )
    assert exc_info.value.security_event is True

    # The nonce was NOT consumed by the mismatch, so the legitimate grant works.
    claims = _verify_delete(token, pub, now, nonce_store)
    assert claims.action == "fs.delete"  # type: ignore[attr-defined]

    # ...and now it is single-use-exhausted.
    with pytest.raises(TokenReplay):
        _verify_delete(token, pub, now, nonce_store)


def test_cross_key_forgery_is_rejected(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    """Assume-Breach: a compromised party signing with its own key cannot mint a
    token the proxy will accept, because the proxy only trusts the control
    plane's public key."""
    _, real_pub = keypair
    attacker_priv, _ = generate_keypair()
    forged = _mint_delete_token(attacker_priv, now)

    with pytest.raises(TokenInvalidSignature) as exc_info:
        _verify_delete(forged, real_pub, now, nonce_store)
    assert exc_info.value.security_event is True


def test_garbage_signature_is_rejected(
    keypair: Keypair, nonce_store: InMemoryNonceStore, now: int
) -> None:
    priv, pub = keypair
    token = _mint_delete_token(priv, now)
    payload_seg, _ = token.split(".")
    tampered = f"{payload_seg}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises((TokenInvalidSignature,)):
        _verify_delete(tampered, pub, now, nonce_store)
