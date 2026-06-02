"""Data-access layer. Profiles are validated through `common.PolicyProfile` on
both write and read so persisted definitions can never drift from the schema the
proxy enforces.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

from common import ConfigBundle, PolicyProfile, now_epoch
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import security
from .config import settings
from .models import AdminSession, AdminUser, Agent, PolicyProfileRow, Tool, utcnow


def _as_aware_utc(dt: datetime) -> datetime:
    # SQLite returns naive datetimes even for tz-aware columns; normalize so
    # expiry comparisons work the same on SQLite and Postgres.
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Admin users + sessions
# --------------------------------------------------------------------------- #
def get_admin_by_username(db: Session, username: str) -> AdminUser | None:
    return db.execute(
        select(AdminUser).where(AdminUser.username == username)
    ).scalar_one_or_none()


def create_admin(db: Session, username: str, password: str, role: str) -> AdminUser:
    admin = AdminUser(
        id=uuid.uuid4().hex,
        username=username,
        password_hash=security.hash_password(password),
        role=role,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin


def create_session(db: Session, admin: AdminUser) -> tuple[str, datetime]:
    token = security.generate_session_token()
    expires_at = utcnow() + timedelta(seconds=settings.session_ttl_seconds)
    db.add(
        AdminSession(
            token_hash=security.hash_session_token(token),
            admin_id=admin.id,
            expires_at=expires_at,
        )
    )
    db.commit()
    return token, expires_at


def get_admin_by_session(db: Session, token_hash: str) -> AdminUser | None:
    session = db.get(AdminSession, token_hash)
    if session is None:
        return None
    if _as_aware_utc(session.expires_at) < datetime.now(UTC):
        return None
    return db.get(AdminUser, session.admin_id)


# --------------------------------------------------------------------------- #
# Policy profiles
# --------------------------------------------------------------------------- #
def get_profile_row(db: Session, profile_id: str) -> PolicyProfileRow | None:
    return db.get(PolicyProfileRow, profile_id)


def get_profile(db: Session, profile_id: str) -> PolicyProfile | None:
    row = db.get(PolicyProfileRow, profile_id)
    return PolicyProfile.model_validate(row.definition) if row is not None else None


def list_profiles(db: Session, tenant: str | None = None) -> list[PolicyProfileRow]:
    stmt = select(PolicyProfileRow)
    if tenant is not None:
        stmt = stmt.where(PolicyProfileRow.tenant == tenant)
    return list(db.execute(stmt).scalars().all())


def create_profile(db: Session, profile: PolicyProfile) -> PolicyProfileRow:
    row = PolicyProfileRow(
        profile_id=profile.profile_id,
        name=profile.name,
        tenant=profile.tenant,
        description=profile.description,
        version=profile.version,
        definition=profile.model_dump(mode="json"),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_profile(
    db: Session, row: PolicyProfileRow, profile: PolicyProfile
) -> PolicyProfileRow:
    row.name = profile.name
    row.tenant = profile.tenant
    row.description = profile.description
    row.version = profile.version
    row.definition = profile.model_dump(mode="json")
    db.commit()
    db.refresh(row)
    return row


def delete_profile(db: Session, row: PolicyProfileRow) -> None:
    db.delete(row)
    db.commit()


def count_agents_on_profile(db: Session, profile_id: str) -> int:
    return db.execute(
        select(func.count()).select_from(Agent).where(Agent.profile_id == profile_id)
    ).scalar_one()


# --------------------------------------------------------------------------- #
# Agents
# --------------------------------------------------------------------------- #
def create_agent(
    db: Session, *, name: str, tenant: str, profile_id: str, credential_hash: str
) -> Agent:
    agent = Agent(
        id=uuid.uuid4().hex,
        name=name,
        tenant=tenant,
        profile_id=profile_id,
        credential_hash=credential_hash,
        status="active",
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


def get_agent(db: Session, agent_id: str) -> Agent | None:
    return db.get(Agent, agent_id)


def get_agent_by_credential(db: Session, credential_hash: str) -> Agent | None:
    return db.execute(
        select(Agent).where(Agent.credential_hash == credential_hash)
    ).scalar_one_or_none()


def list_agents(db: Session, tenant: str | None = None) -> list[Agent]:
    stmt = select(Agent)
    if tenant is not None:
        stmt = stmt.where(Agent.tenant == tenant)
    return list(db.execute(stmt).scalars().all())


def save_agent(db: Session, agent: Agent) -> Agent:
    db.commit()
    db.refresh(agent)
    return agent


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
def get_tool(db: Session, name: str) -> Tool | None:
    return db.get(Tool, name)


def list_tools(db: Session) -> list[Tool]:
    return list(db.execute(select(Tool)).scalars().all())


def upsert_tool(
    db: Session, name: str, json_schema: dict[str, object], default_allow: bool
) -> Tool:
    tool = db.get(Tool, name)
    if tool is None:
        tool = Tool(name=name, json_schema=json_schema, default_allow=default_allow)
        db.add(tool)
    else:
        tool.json_schema = json_schema
        tool.default_allow = default_allow
    db.commit()
    db.refresh(tool)
    return tool


def delete_tool(db: Session, tool: Tool) -> None:
    db.delete(tool)
    db.commit()


# --------------------------------------------------------------------------- #
# Config bundle (pulled by the proxy)
# --------------------------------------------------------------------------- #
def build_config_bundle(db: Session, agent: Agent) -> ConfigBundle | None:
    row = db.get(PolicyProfileRow, agent.profile_id)
    if row is None:
        return None
    profile = PolicyProfile.model_validate(row.definition)
    canonical = json.dumps(row.definition, sort_keys=True, separators=(",", ":"))
    etag = hashlib.sha256(f"{row.version}:{canonical}".encode()).hexdigest()[:32]
    return ConfigBundle(
        agent_id=agent.id,
        profile=profile,
        issued_at=now_epoch(),
        bundle_version=row.version,
        etag=etag,
    )
