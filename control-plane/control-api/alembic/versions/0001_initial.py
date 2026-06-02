"""initial control-plane schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-02

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "admin_users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_admin_users_username", "admin_users", ["username"], unique=True)

    op.create_table(
        "admin_sessions",
        sa.Column("token_hash", sa.String(128), primary_key=True),
        sa.Column(
            "admin_id",
            sa.String(64),
            sa.ForeignKey("admin_users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_admin_sessions_admin_id", "admin_sessions", ["admin_id"])

    op.create_table(
        "policy_profiles",
        sa.Column("profile_id", sa.String(128), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("tenant", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1024), nullable=False, server_default=""),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_profiles_tenant", "policy_profiles", ["tenant"])

    op.create_table(
        "agents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("tenant", sa.String(128), nullable=False),
        sa.Column(
            "profile_id",
            sa.String(128),
            sa.ForeignKey("policy_profiles.profile_id"),
            nullable=False,
        ),
        sa.Column("credential_hash", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agents_tenant", "agents", ["tenant"])
    op.create_index("ix_agents_credential_hash", "agents", ["credential_hash"])

    op.create_table(
        "tools",
        sa.Column("name", sa.String(128), primary_key=True),
        sa.Column("json_schema", sa.JSON(), nullable=False),
        sa.Column("default_allow", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("tools")
    op.drop_index("ix_agents_credential_hash", table_name="agents")
    op.drop_index("ix_agents_tenant", table_name="agents")
    op.drop_table("agents")
    op.drop_index("ix_policy_profiles_tenant", table_name="policy_profiles")
    op.drop_table("policy_profiles")
    op.drop_index("ix_admin_sessions_admin_id", table_name="admin_sessions")
    op.drop_table("admin_sessions")
    op.drop_index("ix_admin_users_username", table_name="admin_users")
    op.drop_table("admin_users")
