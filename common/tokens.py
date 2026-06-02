"""HITL approval-token library — mint (control plane) and verify (data plane).

Threat addressed: **HITL-token replay** and the **Confused-Deputy** problem.
Layer 2 denies any destructive/state-altering action unless the caller presents
an approval token that is:

  * **signature-verified** — minted by the control plane's private key;
  * **scoped** — bound to the exact subject (agent), tenant, action, and resource;
  * **single-use** — carries a nonce (`jti`) consumed against a `NonceStore`;
  * **short-lived** — `issued_at` / `expires_at` window.

Design choices that follow directly from "Assume Breach":

  * **Asymmetric (Ed25519), not HMAC.** Only the control plane holds the signing
    key; proxies hold the public key only. A fully compromised proxy therefore
    *cannot mint* approval tokens — it can only verify them.
  * **Verification is deterministic.** Given the same token, public key, expected
    scope, `now`, and nonce-store state, `verify_hitl_token` always returns the
    same result. (Minting uses a random `jti`, but minting happens on the control
    plane, not on the data-plane decision hot path.)
  * **Claims are parsed only after the signature checks out.** Unsigned bytes are
    never trusted.
  * **The nonce is consumed last** — only after signature, expiry, and scope all
    pass. A validly-signed token presented for the *wrong* action is a scope
    mismatch (a security event) and must NOT burn the nonce, so the legitimate
    holder can still use it for the action it was actually minted for.

Wire format (compact, JWT-like but minimal and dependency-free):

    base64url(canonical_json(claims)) "." base64url(ed25519_signature)

The signature covers ``DOMAIN + "." + <payload-segment-bytes>`` for domain
separation, so a token can never be replayed against a different protocol.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, ValidationError

from .errors import (
    TokenExpired,
    TokenInvalidSignature,
    TokenMalformed,
    TokenNotYetValid,
    TokenReplay,
    TokenScopeMismatch,
)

# Domain-separation tag + version. Bump the version if the claim set or signing
# input ever changes, so old tokens can never validate under new rules.
_DOMAIN = b"MLPEF-HITL-token-v1"
_TOKEN_VERSION = "1"


class HITLTokenClaims(BaseModel):
    """The signed claim set. Timestamps are integer UNIX seconds for an
    unambiguous, canonical byte representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str
    jti: str  # unique nonce — the single-use anchor
    subject: str  # agent identity the approval is bound to
    tenant: str
    action: str  # exact approved action
    resource: str  # exact approved resource
    hitl_request_id: str  # links back to the control-plane HITLRequest
    approver: str  # admin user who approved (for the audit trail)
    issued_at: int
    expires_at: int


# --------------------------------------------------------------------------- #
# Single-use nonce ledger
# --------------------------------------------------------------------------- #
@runtime_checkable
class NonceStore(Protocol):
    """Records consumed token nonces to enforce single use.

    Production binds this to Postgres/Redis with an atomic check-and-set so that
    two concurrent verifications of the same token cannot both succeed.
    """

    def consume(self, jti: str, expires_at: int) -> bool:
        """Atomically mark `jti` consumed.

        Returns True if this call consumed it for the first time, False if it
        was already consumed (i.e. a replay).
        """
        ...


class InMemoryNonceStore:
    """In-process `NonceStore` for tests and single-instance dev.

    Not suitable for a horizontally-scaled proxy fleet (state is per-process);
    swap in a shared-store implementation in Phase 2/8.
    """

    def __init__(self) -> None:
        self._consumed: dict[str, int] = {}

    def consume(self, jti: str, expires_at: int) -> bool:
        if jti in self._consumed:
            return False
        self._consumed[jti] = expires_at
        return True

    def prune(self, now: int) -> int:
        """Drop entries whose tokens have expired. Returns the count removed."""
        expired = [jti for jti, exp in self._consumed.items() if exp < now]
        for jti in expired:
            del self._consumed[jti]
        return len(expired)


# --------------------------------------------------------------------------- #
# base64url helpers (no padding, per RFC 7515 §2)
# --------------------------------------------------------------------------- #
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _canonical_payload(claims: HITLTokenClaims) -> bytes:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(
        claims.model_dump(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _signing_input(payload_segment: str) -> bytes:
    return _DOMAIN + b"." + payload_segment.encode("ascii")


# --------------------------------------------------------------------------- #
# Mint (control plane — holds the private key)
# --------------------------------------------------------------------------- #
def mint_hitl_token(
    private_key: Ed25519PrivateKey,
    *,
    subject: str,
    tenant: str,
    action: str,
    resource: str,
    hitl_request_id: str,
    approver: str,
    issued_at: int,
    ttl_seconds: int,
    jti: str | None = None,
) -> str:
    """Mint a scoped, single-use, expiring approval token.

    Called by the control plane when an approver acts on an HITLRequest in the
    UI. `ttl_seconds` should be short (e.g. 120-300s). `jti` is generated with a
    CSPRNG when not supplied.
    """
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")

    claims = HITLTokenClaims(
        version=_TOKEN_VERSION,
        jti=jti if jti is not None else secrets.token_urlsafe(32),
        subject=subject,
        tenant=tenant,
        action=action,
        resource=resource,
        hitl_request_id=hitl_request_id,
        approver=approver,
        issued_at=issued_at,
        expires_at=issued_at + ttl_seconds,
    )
    payload_segment = _b64url_encode(_canonical_payload(claims))
    signature = private_key.sign(_signing_input(payload_segment))
    return f"{payload_segment}.{_b64url_encode(signature)}"


# --------------------------------------------------------------------------- #
# Verify (data plane — holds the public key only)
# --------------------------------------------------------------------------- #
def verify_hitl_token(
    token: str,
    public_key: Ed25519PublicKey,
    *,
    expected_subject: str,
    expected_tenant: str,
    expected_action: str,
    expected_resource: str,
    now: int,
    nonce_store: NonceStore,
    leeway_seconds: int = 0,
) -> HITLTokenClaims:
    """Verify and consume an approval token, or raise a typed `TokenError`.

    Verification order is deliberate and fail-closed:
      1. structural parse           -> TokenMalformed
      2. signature over the raw segment -> TokenInvalidSignature  (before trusting
         any claim)
      3. claims parse + version     -> TokenMalformed
      4. time window                -> TokenNotYetValid / TokenExpired
      5. scope binding              -> TokenScopeMismatch  (security event)
      6. single-use nonce (LAST)    -> TokenReplay

    `leeway_seconds` permits small clock skew between the minting control plane
    and the verifying proxy; default 0 keeps verification fully deterministic.
    """
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise TokenMalformed("token must have exactly two non-empty segments")
    payload_segment, signature_segment = parts

    try:
        signature = _b64url_decode(signature_segment)
    except ValueError as exc:  # binascii.Error subclasses ValueError
        raise TokenMalformed("signature segment is not valid base64url") from exc

    # (2) Authenticate the bytes BEFORE parsing any claim.
    try:
        public_key.verify(signature, _signing_input(payload_segment))
    except InvalidSignature as exc:
        raise TokenInvalidSignature("approval-token signature failed to verify") from exc

    # (3) Now it is safe to decode and validate the claims.
    try:
        raw = _b64url_decode(payload_segment)
        data: Any = json.loads(raw)
    except ValueError as exc:  # covers binascii.Error + json.JSONDecodeError
        raise TokenMalformed("payload segment is not valid base64url JSON") from exc

    try:
        claims = HITLTokenClaims.model_validate(data)
    except ValidationError as exc:
        raise TokenMalformed("approval-token claims failed schema validation") from exc

    if claims.version != _TOKEN_VERSION:
        raise TokenMalformed(f"unsupported token version: {claims.version!r}")

    # (4) Time window.
    if now + leeway_seconds < claims.issued_at:
        raise TokenNotYetValid("approval token is not yet valid")
    if now - leeway_seconds > claims.expires_at:
        raise TokenExpired("approval token has expired")

    # (5) Scope binding — a validly-signed token used outside its grant is the
    # Confused-Deputy signal. Do NOT consume the nonce on mismatch.
    if (
        claims.subject != expected_subject
        or claims.tenant != expected_tenant
        or claims.action != expected_action
        or claims.resource != expected_resource
    ):
        raise TokenScopeMismatch(
            "approval token does not match the requested subject/action/resource",
            detail={
                "expected_action": expected_action,
                "token_action": claims.action,
                "hitl_request_id": claims.hitl_request_id,
            },
        )

    # (6) Single-use — consume last, only once everything else has passed.
    if not nonce_store.consume(claims.jti, claims.expires_at):
        raise TokenReplay("approval token has already been used")

    return claims


# --------------------------------------------------------------------------- #
# Key management helpers
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair (used by the seed script and tests)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def load_private_key_pem(data: bytes, password: bytes | None = None) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected an Ed25519 private key in PEM data")
    return key


def load_public_key_pem(data: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key in PEM data")
    return key


def private_key_to_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
