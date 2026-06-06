"""hitl single-use nonce ledger

Revision ID: 0004_hitl_nonces
Revises: 0003_hitl
Create Date: 2026-06-06

"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_hitl_nonces"
down_revision = "0003_hitl"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Shared single-use ledger: the jti primary key makes consumption an atomic
    # check-and-set across a scaled proxy fleet (R-2).
    op.create_table(
        "hitl_nonces",
        sa.Column("jti", sa.String(64), primary_key=True),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("consumed_at", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("hitl_nonces")
