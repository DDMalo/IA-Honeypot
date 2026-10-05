"""Per-hash intelligence for captured files.

Keyed by the hash rather than hung off `file_transfers`, because one dropper
appears in hundreds of transfers and the lookup behind this table is limited
to four requests a minute.

Revision ID: 4f2c71e0a93b
Revises: d8a0bbb028ad
Create Date: 2026-10-05 18:05:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "4f2c71e0a93b"
down_revision: str | None = "d8a0bbb028ad"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "file_intel",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("known", sa.Boolean(), nullable=False),
        sa.Column("malicious", sa.Integer(), nullable=True),
        sa.Column("suspicious", sa.Integer(), nullable=True),
        sa.Column("harmless", sa.Integer(), nullable=True),
        sa.Column("undetected", sa.Integer(), nullable=True),
        sa.Column("threat_label", sa.Text(), nullable=True),
        sa.Column("file_type", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_analysis_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vt_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("sha256"),
    )
    op.create_index("ix_file_intel_known", "file_intel", ["known"], unique=False)
    op.create_index("ix_file_intel_threat_label", "file_intel", ["threat_label"], unique=False)
    op.create_index("ix_file_intel_vt_checked_at", "file_intel", ["vt_checked_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_file_intel_vt_checked_at", table_name="file_intel")
    op.drop_index("ix_file_intel_threat_label", table_name="file_intel")
    op.drop_index("ix_file_intel_known", table_name="file_intel")
    op.drop_table("file_intel")
