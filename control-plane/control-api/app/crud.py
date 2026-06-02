"""Data-access layer. Profiles are validated through `common.PolicyProfile` on
both write and read so persisted definitions can never drift from the schema the
proxy enforces.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from common import (
    GENESIS_PREV_HASH,
    AuditEvent,
    AuditRecord,
    ChainVerification,
    ConfigBundle,
    PolicyProfile,
    now_epoch,
    seal_event,
    verify_chain,
)

from . import security
from .config import settings
from .models import (
    AdminSession,
    AdminUser,
    Agent,
    AuditRecordRow,
    PolicyProfileRow,
    Tool,
    utcnow,
)


def _as_aware_utc(dt: datetime) -> datetime:
    # SQLite returns naive datetimes even for tz-aware columns; normalize so
    # expiry comparisons work the same on SQLite and Postgres.
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


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
    if _as_aware_utc(session.expires_at) < datetime.now(timezone.utc):
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


# --------------------------------------------------------------------------- #
# Audit store — server-sealed, tamper-evident chain
# --------------------------------------------------------------------------- #
def _row_to_record(row: AuditRecordRow) -> AuditRecord:
    return AuditRecord(
        seq=row.seq,
        prev_hash=row.prev_hash,
        recorded_at=row.recorded_at,
        event=AuditEvent.model_validate(row.event),
        record_hash=row.record_hash,
    )


def append_audit_event(db: Session, event: AuditEvent) -> AuditRecord:
    # Single-writer append: link to the current tail, then seal. (Concurrency
    # hardening — SELECT ... FOR UPDATE / single-writer queue — tracked as a
    # residual risk; see THREAT_MODEL.md R-16.)
    last = db.execute(
        select(AuditRecordRow).order_by(AuditRecordRow.seq.desc()).limit(1)
    ).scalar_one_or_none()
    seq = last.seq + 1 if last is not None else 0
    prev_hash = last.record_hash if last is not None else GENESIS_PREV_HASH
    record = seal_event(event, seq=seq, prev_hash=prev_hash, recorded_at=now_epoch())
    db.add(
        AuditRecordRow(
            seq=record.seq,
            correlation_id=event.correlation_id,
            agent_id=event.agent_id,
            tenant=event.tenant,
            action=event.action,
            final_verdict=event.final_verdict.value,
            security_event=event.security_event,
            timestamp=event.timestamp,
            recorded_at=record.recorded_at,
            prev_hash=record.prev_hash,
            record_hash=record.record_hash,
            event=event.model_dump(mode="json"),
        )
    )
    db.commit()
    return record


def list_audit(
    db: Session,
    *,
    agent_id: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    correlation_id: str | None = None,
    security_event: bool | None = None,
    limit: int = 100,
) -> list[AuditRecord]:
    stmt = select(AuditRecordRow).order_by(AuditRecordRow.seq.asc())
    if agent_id is not None:
        stmt = stmt.where(AuditRecordRow.agent_id == agent_id)
    if action is not None:
        stmt = stmt.where(AuditRecordRow.action == action)
    if outcome is not None:
        stmt = stmt.where(AuditRecordRow.final_verdict == outcome)
    if correlation_id is not None:
        stmt = stmt.where(AuditRecordRow.correlation_id == correlation_id)
    if security_event is not None:
        stmt = stmt.where(AuditRecordRow.security_event == security_event)
    stmt = stmt.limit(limit)
    return [_row_to_record(r) for r in db.execute(stmt).scalars().all()]


def verify_audit_chain(db: Session) -> ChainVerification:
    rows = db.execute(select(AuditRecordRow).order_by(AuditRecordRow.seq.asc())).scalars().all()
    return verify_chain([_row_to_record(r) for r in rows])
