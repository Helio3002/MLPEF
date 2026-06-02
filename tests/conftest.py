"""Shared pytest fixtures for the common-layer test suite."""

from __future__ import annotations

import pytest
from common import InMemoryNonceStore, generate_keypair
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# A fixed reference time so token-expiry tests are deterministic.
NOW = 1_700_000_000


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    return generate_keypair()


@pytest.fixture
def nonce_store() -> InMemoryNonceStore:
    return InMemoryNonceStore()


@pytest.fixture
def now() -> int:
    return NOW
