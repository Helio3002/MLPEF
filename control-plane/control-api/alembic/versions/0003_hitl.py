"""hitl requests table

Revision ID: 0003_hitl
Revises: 0002_audit
Create Date: 2026-06-03

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_hitl"
down_revision = "0002_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hitl_requests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("tenant", sa.String(128), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("approver", sa.String(64), nullable=True),
        sa.Column("token_jti", sa.String(64), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_hitl_requests_agent_id", "hitl_requests", ["agent_id"])
    op.create_index("ix_hitl_requests_tenant", "hitl_requests", ["tenant"])
    op.create_index("ix_hitl_requests_status", "hitl_requests", ["status"])


def downgrade() -> None:
    op.drop_table("hitl_requests")
