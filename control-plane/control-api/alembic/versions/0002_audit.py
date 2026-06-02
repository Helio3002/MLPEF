"""audit records table

Revision ID: 0002_audit
Revises: 0001_initial
Create Date: 2026-06-03

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_audit"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_records",
        sa.Column("seq", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(64), nullable=False),
        sa.Column("tenant", sa.String(128), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("final_verdict", sa.String(32), nullable=False),
        sa.Column("security_event", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("timestamp", sa.Integer(), nullable=False),
        sa.Column("recorded_at", sa.Integer(), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        sa.Column("event", sa.JSON(), nullable=False),
    )
    op.create_index("ix_audit_records_correlation_id", "audit_records", ["correlation_id"])
    op.create_index("ix_audit_records_agent_id", "audit_records", ["agent_id"])
    op.create_index("ix_audit_records_tenant", "audit_records", ["tenant"])
    op.create_index("ix_audit_records_action", "audit_records", ["action"])
    op.create_index("ix_audit_records_final_verdict", "audit_records", ["final_verdict"])
    op.create_index("ix_audit_records_security_event", "audit_records", ["security_event"])
    op.create_index("ix_audit_records_record_hash", "audit_records", ["record_hash"])


def downgrade() -> None:
    op.drop_table("audit_records")
