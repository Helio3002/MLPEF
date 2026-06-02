"""Control-plane HITL token signing key (Ed25519).

The control plane is the ONLY holder of the private signing key; proxies receive
the public key (GET /hitl/public-key) and can only verify, never mint. Load the
key from MLPEF_HITL_PRIVATE_KEY_PEM; if unset, generate an ephemeral key at
startup — dev only: tokens will not verify across restarts (they are short-lived
anyway). See THREAT_MODEL.md R-8 (key compromise) and R-22 (ephemeral dev key).
"""

from __future__ import annotations

import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from common import generate_keypair, load_private_key_pem, public_key_to_pem


def _load() -> Ed25519PrivateKey:
    pem = os.environ.get("MLPEF_HITL_PRIVATE_KEY_PEM")
    if pem:
        return load_private_key_pem(pem.encode("utf-8"))
    private_key, _ = generate_keypair()
    print(
        "[signing] WARNING: MLPEF_HITL_PRIVATE_KEY_PEM is unset — using an ephemeral "
        "dev signing key. Tokens will not verify across restarts; set the env var "
        "(from a secret manager) in production.",
        file=sys.stderr,
    )
    return private_key


_PRIVATE_KEY = _load()


def signing_key() -> Ed25519PrivateKey:
    return _PRIVATE_KEY


def public_key_pem() -> str:
    return public_key_to_pem(_PRIVATE_KEY.public_key()).decode("utf-8")
