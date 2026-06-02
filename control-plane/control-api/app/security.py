"""Credential primitives — stdlib only (no bcrypt/passlib dependency).

- Admin passwords: PBKDF2-HMAC-SHA256 with a per-password random salt. Verified
  in constant time.
- Agent API keys: high-entropy random tokens; only their SHA-256 is stored. A
  fast hash is appropriate here because the input is already 256 bits of entropy
  (no brute-force surface), unlike low-entropy human passwords.
- Admin session tokens: random, stored as SHA-256.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

_PBKDF2_ALGO = "pbkdf2_sha256"
_PBKDF2_ROUNDS = 200_000
_SALT_BYTES = 16
_API_KEY_PREFIX = "mlpef_"


def hash_password(password: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"{_PBKDF2_ALGO}${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, rounds_str, salt_hex, dk_hex = encoded.split("$")
        rounds = int(rounds_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
    except (ValueError, AttributeError):
        return False
    if algo != _PBKDF2_ALGO:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(candidate, expected)


def generate_api_key() -> str:
    return _API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
