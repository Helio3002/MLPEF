"""Config-bundle signing — control plane signs, data plane verifies.

The proxy caches the policy `ConfigBundle` it pulls from the control plane. Under
**assume breach**, transport security (TLS) is not sufficient: a compromised
network position or an impersonated control plane could feed the proxy a *more
permissive* bundle. So the control plane signs the bundle with its Ed25519 private
key — the same key family as HITL tokens, under a **distinct domain tag** so a
config signature can never be confused with a token signature — and the proxy
verifies it with the public key it already holds. The proxy refuses to apply an
unsigned or tampered bundle (fail closed). The proxy holds the public key only, so
a compromised proxy still cannot forge a bundle.

The signature covers a canonical JSON serialization of the bundle with the
`signature` field removed, so signing and verification operate on identical bytes.
"""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ConfigBundleUntrusted
from .profiles import ConfigBundle

# Domain-separation tag + version, distinct from the HITL-token domain. Bump the
# version if the signed-bytes construction ever changes.
_CONFIG_DOMAIN = b"MLPEF-config-bundle-v1"


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _canonical_payload(bundle: ConfigBundle) -> bytes:
    """Deterministic JSON of the bundle, excluding the signature field itself."""
    data = bundle.model_dump(mode="json", exclude={"signature"})
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _signing_input(payload: bytes) -> bytes:
    return _CONFIG_DOMAIN + b"." + payload


def sign_config_bundle(bundle: ConfigBundle, private_key: Ed25519PrivateKey) -> str:
    """Return the base64url Ed25519 signature over the bundle (excluding `signature`).

    Caller sets it on the bundle, e.g. ``bundle.model_copy(update={"signature": sig})``.
    """
    signature = private_key.sign(_signing_input(_canonical_payload(bundle)))
    return _b64url_encode(signature)


def verify_config_bundle(bundle: ConfigBundle, public_key: Ed25519PublicKey) -> None:
    """Verify the bundle's signature, or raise `ConfigBundleUntrusted` (fail closed).

    Authenticates the bytes before they are trusted: an absent, malformed, or
    invalid signature all raise — the proxy must never apply such a bundle.
    """
    if not bundle.signature:
        raise ConfigBundleUntrusted(
            "config bundle is unsigned", detail={"agent_id": bundle.agent_id}
        )
    try:
        signature = _b64url_decode(bundle.signature)
    except ValueError as exc:  # binascii.Error subclasses ValueError
        raise ConfigBundleUntrusted(
            "config bundle signature is not valid base64url",
            detail={"agent_id": bundle.agent_id},
        ) from exc
    try:
        public_key.verify(signature, _signing_input(_canonical_payload(bundle)))
    except InvalidSignature as exc:
        raise ConfigBundleUntrusted(
            "config bundle signature failed to verify",
            detail={"agent_id": bundle.agent_id},
        ) from exc
