"""Reputation columns on ip_intel.

Added to the existing per-address table rather than a table of their own: one
address has one reputation, so a second table would be a one-to-one join on
every query for nothing in return.

Revision ID: d8a0bbb028ad
Revises: b176a98eaeba
Create Date: 2026-10-05 17:40:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d8a0bbb028ad"
down_revision: str | None = "b176a98eaeba"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ip_intel", sa.Column("abuse_score", sa.Integer(), nullable=True))
    op.add_column("ip_intel", sa.Column("abuse_reports", sa.Integer(), nullable=True))
    op.add_column("ip_intel", sa.Column("abuse_reporters", sa.Integer(), nullable=True))
    op.add_column(
        "ip_intel",
        sa.Column("abuse_last_reported_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("ip_intel", sa.Column("abuse_isp", sa.Text(), nullable=True))
    op.add_column("ip_intel", sa.Column("abuse_usage_type", sa.Text(), nullable=True))
    op.add_column("ip_intel", sa.Column("abuse_domain", sa.Text(), nullable=True))
    op.add_column("ip_intel", sa.Column("abuse_is_tor", sa.Boolean(), nullable=True))
    op.add_column(
        "ip_intel",
        sa.Column("abuse_checked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_ip_intel_abuse_score", "ip_intel", ["abuse_score"], unique=False)
    op.create_index("ix_ip_intel_abuse_checked_at", "ip_intel", ["abuse_checked_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_ip_intel_abuse_checked_at", table_name="ip_intel")
    op.drop_index("ix_ip_intel_abuse_score", table_name="ip_intel")
    op.drop_column("ip_intel", "abuse_checked_at")
    op.drop_column("ip_intel", "abuse_is_tor")
    op.drop_column("ip_intel", "abuse_domain")
    op.drop_column("ip_intel", "abuse_usage_type")
    op.drop_column("ip_intel", "abuse_isp")
    op.drop_column("ip_intel", "abuse_last_reported_at")
    op.drop_column("ip_intel", "abuse_reporters")
    op.drop_column("ip_intel", "abuse_reports")
    op.drop_column("ip_intel", "abuse_score")
