"""Relational schema for honeypot sessions.

The shape mirrors `honeypot_ai.models`: one row per session, with child tables
for the things that repeat inside it. Three decisions are worth stating.

**Cowrie's session id is the primary key.** It is already unique per
connection, so re-ingesting the same log updates rows instead of duplicating
them. Ingestion can therefore be re-run over the whole file at any time, which
is what makes the pipeline recoverable.

**Child rows carry a sequence number.** `(session_id, seq)` is unique, so an
attacker who types the same command twice is recorded twice, while re-reading
the same log twice is not.

**Addresses are stored as `inet`.** PostgreSQL then understands them as
addresses rather than strings, so queries can ask for a whole subnet — the
natural way to spot one actor spraying from a range.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for every table in the project."""


class SessionRow(Base):
    """One connection to the honeypot.

    `authenticated` and `command_count` duplicate information held in the child
    tables. That is deliberate: almost every question asked of this data starts
    by separating the sessions that got in and did something from the vast
    majority that only guessed passwords, and it should not need a join.
    """

    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    sensor: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    client_version: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Float)

    authenticated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    command_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    login_attempts: Mapped[list[LoginAttemptRow]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True
    )
    commands: Mapped[list[CommandRow]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True
    )
    file_transfers: Mapped[list[FileTransferRow]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        CheckConstraint(
            "protocol IS NULL OR protocol IN ('ssh', 'telnet')", name="ck_sessions_protocol"
        ),
        # Most dashboards ask "what happened recently" or "what has this
        # address been doing"; both deserve an index from the start.
        Index("ix_sessions_started_at", "started_at"),
        Index("ix_sessions_src_ip", "src_ip"),
        # Interactive sessions are a small fraction of the whole and are read
        # far more often, so they get a partial index of their own.
        Index(
            "ix_sessions_interactive",
            "started_at",
            postgresql_where=(command_count > 0),
        ),
    )


class LoginAttemptRow(Base):
    """One credential pair tried in a session."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)

    username: Mapped[str] = mapped_column(Text, nullable=False)
    password: Mapped[str] = mapped_column(Text, nullable=False)
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    session: Mapped[SessionRow] = relationship(back_populates="login_attempts")

    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_login_attempts_session_seq"),
        # "Which credentials are being sprayed this week" is the first question
        # anyone asks of honeypot data.
        Index("ix_login_attempts_username", "username"),
        Index("ix_login_attempts_password", "password"),
    )


class CommandRow(Base):
    """One command typed into the emulated shell.

    `failed` marks commands Cowrie does not emulate. Those are kept because
    they reveal what the attacker expected to find on the machine.
    """

    __tablename__ = "commands"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)

    input: Mapped[str] = mapped_column(Text, nullable=False)
    failed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    session: Mapped[SessionRow] = relationship(back_populates="commands")

    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_commands_session_seq"),
        Index("ix_commands_occurred_at", "occurred_at"),
    )


class FileTransferRow(Base):
    """A file an attacker tried to fetch, or uploaded.

    Only the URL and the hash are stored. Samples never leave the sensor, and
    the hash is enough to look a file up in VirusTotal or MalwareBazaar.
    """

    __tablename__ = "file_transfers"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)

    url: Mapped[str | None] = mapped_column(Text)
    shasum: Mapped[str | None] = mapped_column(String(64))
    uploaded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    session: Mapped[SessionRow] = relationship(back_populates="file_transfers")

    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_file_transfers_session_seq"),
        Index("ix_file_transfers_shasum", "shasum"),
    )
