"""Runtime settings, read from the environment.

Secrets and connection strings come from env / a secret manager only — never
committed. SQLite is the zero-setup default for local dev and tests; Postgres is
used in docker-compose and production (set DATABASE_URL).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str
    session_ttl_seconds: int
    agent_key_header: str
    hitl_token_ttl_seconds: int

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            database_url=os.environ.get("DATABASE_URL", "sqlite:///./mlpef_control.db"),
            session_ttl_seconds=int(os.environ.get("MLPEF_SESSION_TTL_SECONDS", "43200")),
            agent_key_header=os.environ.get("MLPEF_AGENT_KEY_HEADER", "X-Agent-Key"),
            hitl_token_ttl_seconds=int(os.environ.get("MLPEF_HITL_TOKEN_TTL_SECONDS", "300")),
        )


settings = Settings.from_env()
