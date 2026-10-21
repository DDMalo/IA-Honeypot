"""Classifier output, one row per session per classifier.

Keyed by `(session_id, classifier)` rather than by session alone, so the rule
engine, each language model and later a human analyst all record their own
answer for the same session. Where they agree there is nothing to learn; where
they disagree is the entire basis of the evaluation in v0.5.0, and a table
holding one label per session cannot represent it.

Revision ID: b7e4a1c0d562
Revises: 4f2c71e0a93b
Create Date: 2026-10-21 18:00:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7e4a1c0d562"
down_revision: str | None = "4f2c71e0a93b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "session_labels",
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("classifier", sa.String(length=64), nullable=False),
        sa.Column("intent", sa.String(length=32), nullable=False),
        sa.Column(
            "behaviours",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("operator", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("taxonomy_version", sa.Integer(), nullable=False),
        sa.Column(
            "labelled_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["session_id"], ["sessions.session_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("session_id", "classifier"),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_session_labels_confidence"
        ),
    )
    op.create_index(
        "ix_session_labels_classifier_intent",
        "session_labels",
        ["classifier", "intent"],
        unique=False,
    )
    op.create_index("ix_session_labels_intent", "session_labels", ["intent"], unique=False)
    op.create_index(
        "ix_session_labels_taxonomy_version",
        "session_labels",
        ["taxonomy_version"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_session_labels_taxonomy_version", table_name="session_labels")
    op.drop_index("ix_session_labels_intent", table_name="session_labels")
    op.drop_index("ix_session_labels_classifier_intent", table_name="session_labels")
    op.drop_table("session_labels")
