"""Control-plane persistence models (SQLAlchemy 2.0, DB-agnostic types).

The rich nested PolicyProfile (see common.profiles) is stored as a JSON
`definition` plus mirrored scalar columns (name/tenant/version) for listing and
filtering. Agents reference a profile by its logical `profile_id`, so editing one
profile reconfigures every agent on it — the central-config requirement.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # One of: superadmin | security-reviewer | approver | read-only
    role: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AdminSession(Base):
    __tablename__ = "admin_sessions"

    token_hash: Mapped[str] = mapped_column(String(128), primary_key=True)
    admin_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("admin_users.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class PolicyProfileRow(Base):
    __tablename__ = "policy_profiles"

    profile_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    description: Mapped[str] = mapped_column(String(1024), default="")
    version: Mapped[int] = mapped_column(Integer, default=1)
    # Full common.PolicyProfile dump; validated on the way in and out.
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    profile_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("policy_profiles.profile_id")
    )
    # SHA-256 hex of the high-entropy API key. The plaintext key is shown once at
    # registration and never stored.
    credential_hash: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | suspended
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Tool(Base):
    __tablename__ = "tools"

    name: Mapped[str] = mapped_column(String(128), primary_key=True)
    json_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    default_allow: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class AuditRecordRow(Base):
    """One sealed, hash-chained audit entry. `seq` is the chain position; the
    store assigns it (single writer). Scalar columns mirror the JSON `event` for
    filtering; `prev_hash`/`record_hash` carry the tamper-evident chain."""

    __tablename__ = "audit_records"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(255), index=True)
    final_verdict: Mapped[str] = mapped_column(String(32), index=True)
    security_event: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    timestamp: Mapped[int] = mapped_column(Integer)
    recorded_at: Mapped[int] = mapped_column(Integer)
    prev_hash: Mapped[str] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64), index=True)
    event: Mapped[dict[str, Any]] = mapped_column(JSON)
