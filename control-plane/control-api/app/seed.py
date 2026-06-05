"""Seed an admin user, the deny-most default profile, and a sample agent.

Run from this directory:  python -m app.seed

For real deployments, run `alembic upgrade head` first. This script also calls
create_all() as a convenience for quick local starts without Alembic; if you use
Alembic, run it BEFORE seeding (never the other way around).
"""

from __future__ import annotations

import os

from common import default_locked_down_profile

from . import crud, security
from .db import Base, SessionLocal, engine

_DEFAULT_PROFILE_ID = "default-locked-down"


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin_username = os.environ.get("MLPEF_ADMIN_USERNAME", "admin")
        admin_password = os.environ.get("MLPEF_ADMIN_PASSWORD", "admin")
        if crud.get_admin_by_username(db, admin_username) is None:
            crud.create_admin(db, admin_username, admin_password, "superadmin")
            print(f"[seed] created superadmin '{admin_username}'")
            if admin_password == "admin":
                print("[seed] WARNING: using default password 'admin' — set MLPEF_ADMIN_PASSWORD")
        else:
            print(f"[seed] admin '{admin_username}' already exists; skipping")

        if crud.get_profile_row(db, _DEFAULT_PROFILE_ID) is None:
            profile = default_locked_down_profile("default", profile_id=_DEFAULT_PROFILE_ID)
            crud.create_profile(db, profile)
            print(f"[seed] created '{_DEFAULT_PROFILE_ID}' profile (deny-most)")
        else:
            print(f"[seed] profile '{_DEFAULT_PROFILE_ID}' already exists; skipping")

        if not any(a.name == "sample-agent" for a in crud.list_agents(db)):
            # Opt-in fixed demo credential: if BOTH env vars are set (docker-compose
            # demo), create the sample agent with a reproducible id + key so the
            # sample-agent container can authenticate without a copy/paste step.
            # Unset (the default / any real deploy) keeps a random key shown once.
            fixed_id = os.environ.get("MLPEF_SAMPLE_AGENT_ID")
            fixed_key = os.environ.get("MLPEF_SAMPLE_AGENT_API_KEY")
            if fixed_id and fixed_key:
                api_key = fixed_key
                agent = crud.create_agent(
                    db,
                    name="sample-agent",
                    tenant="default",
                    profile_id=_DEFAULT_PROFILE_ID,
                    credential_hash=security.hash_api_key(api_key),
                    agent_id=fixed_id,
                )
                print(
                    "[seed] WARNING: created 'sample-agent' with a FIXED demo "
                    "credential from the environment — never do this in production."
                )
            else:
                api_key = security.generate_api_key()
                agent = crud.create_agent(
                    db,
                    name="sample-agent",
                    tenant="default",
                    profile_id=_DEFAULT_PROFILE_ID,
                    credential_hash=security.hash_api_key(api_key),
                )
                print(f"[seed] created 'sample-agent' — API key (shown once): {api_key}")
            print(f"[seed] sample-agent id = {agent.id}")
        else:
            print("[seed] 'sample-agent' already exists; skipping")
    finally:
        db.close()


if __name__ == "__main__":
    main()
