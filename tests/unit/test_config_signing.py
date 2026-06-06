"""Config-bundle signing/verification (R-12).

Proves the assume-breach guarantee: the proxy applies a bundle only if it carries
a valid control-plane signature. Tampering (a more permissive profile), an absent
signature, a wrong key, or garbage bytes all fail closed.
"""

from __future__ import annotations

import pytest
from common import (
    ConfigBundle,
    ConfigBundleUntrusted,
    default_locked_down_profile,
    generate_keypair,
    sign_config_bundle,
    verify_config_bundle,
)


def _bundle(*, profile_id: str = "p") -> ConfigBundle:
    return ConfigBundle(
        agent_id="agent-1",
        profile=default_locked_down_profile("t", profile_id=profile_id),
        issued_at=1_700_000_000,
        bundle_version=1,
        etag="etag-abc",
    )


def test_sign_then_verify_roundtrips() -> None:
    priv, pub = generate_keypair()
    bundle = _bundle()
    signed = bundle.model_copy(update={"signature": sign_config_bundle(bundle, priv)})
    assert signed.signature
    verify_config_bundle(signed, pub)  # must not raise


def test_unsigned_bundle_is_untrusted() -> None:
    _, pub = generate_keypair()
    with pytest.raises(ConfigBundleUntrusted):
        verify_config_bundle(_bundle(), pub)


def test_tampered_profile_fails_verification() -> None:
    priv, pub = generate_keypair()
    bundle = _bundle()
    signed = bundle.model_copy(update={"signature": sign_config_bundle(bundle, priv)})
    # Attacker swaps in a permissive allowlist but keeps the original signature.
    permissive = signed.profile.model_copy(update={"tool_allowlist": ["shell.exec"]})
    tampered = signed.model_copy(update={"profile": permissive})
    with pytest.raises(ConfigBundleUntrusted):
        verify_config_bundle(tampered, pub)


def test_cross_key_signature_rejected() -> None:
    priv_a, _ = generate_keypair()
    _, pub_b = generate_keypair()
    bundle = _bundle()
    signed = bundle.model_copy(update={"signature": sign_config_bundle(bundle, priv_a)})
    with pytest.raises(ConfigBundleUntrusted):
        verify_config_bundle(signed, pub_b)


def test_garbage_signature_rejected() -> None:
    _, pub = generate_keypair()
    bundle = _bundle().model_copy(update={"signature": "not-a-real-signature"})
    with pytest.raises(ConfigBundleUntrusted):
        verify_config_bundle(bundle, pub)
