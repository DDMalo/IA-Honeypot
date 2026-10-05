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


class IpIntelRow(Base):
    """What is known about one source address, independent of any session.

    Addresses repeat heavily — a single bot hammers the honeypot for hours —
    so this is keyed by address rather than carried on every session. One
    lookup then serves thousands of rows, which matters because the data
    behind it is rate-limited, paid for, or both.

    Geolocation is an estimate, not a fact. It places the machine sending the
    packets, which for a botnet is a compromised host rather than an attacker,
    and city-level accuracy is poor. `country_code` and `asn` are the fields
    worth drawing conclusions from; the coordinates are for drawing a map.
    """

    __tablename__ = "ip_intel"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)

    country_code: Mapped[str | None] = mapped_column(String(2))
    country_name: Mapped[str | None] = mapped_column(Text)
    city: Mapped[str | None] = mapped_column(Text)
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)

    asn: Mapped[int | None] = mapped_column(Integer)
    as_org: Mapped[str | None] = mapped_column(Text)

    # Null when the databases had no entry for this address, which happens and
    # must be distinguishable from "not looked up yet".
    geo_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Reputation, from AbuseIPDB. `abuse_score` is a 0-100 confidence that the
    # address is a source of abuse, derived from reports other people filed —
    # evidence, not a verdict, and biased towards ranges people bother to
    # report. `abuse_usage_type` is the more interesting field: it separates a
    # rented datacentre machine from a residential address, which is usually a
    # compromised router rather than an attacker's own computer.
    abuse_score: Mapped[int | None] = mapped_column(Integer)
    abuse_reports: Mapped[int | None] = mapped_column(Integer)
    abuse_reporters: Mapped[int | None] = mapped_column(Integer)
    abuse_last_reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    abuse_isp: Mapped[str | None] = mapped_column(Text)
    abuse_usage_type: Mapped[str | None] = mapped_column(Text)
    abuse_domain: Mapped[str | None] = mapped_column(Text)
    abuse_is_tor: Mapped[bool | None] = mapped_column(Boolean)

    # Unlike geolocation, reputation goes stale: this is both "have we asked"
    # and "how long ago", and the worker re-checks on it.
    abuse_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_ip_intel_country_code", "country_code"),
        Index("ix_ip_intel_asn", "asn"),
        Index("ix_ip_intel_abuse_score", "abuse_score"),
        # The reputation worker's selection query asks for exactly this:
        # addresses never checked, or checked before a cutoff.
        Index("ix_ip_intel_abuse_checked_at", "abuse_checked_at"),
    )


class FileIntelRow(Base):
    """What is known about one captured file, keyed by its hash.

    Separate from `file_transfers` because the same dropper turns up in
    hundreds of sessions: one lookup serves all of them, and the service it
    comes from allows four requests a minute.

    `known` is the field to branch on. False means VirusTotal has never been
    sent this file by anyone — which, for a honeypot, is the most interesting
    answer there is. It is recorded rather than treated as a failed lookup.

    No sample is stored here, or anywhere else in the repository. Only the
    hash, and what other people already know about it.
    """

    __tablename__ = "file_intel"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)

    known: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    malicious: Mapped[int | None] = mapped_column(Integer)
    suspicious: Mapped[int | None] = mapped_column(Integer)
    harmless: Mapped[int | None] = mapped_column(Integer)
    undetected: Mapped[int | None] = mapped_column(Integer)

    # VirusTotal's own consensus name, e.g. "trojan.mirai/gafgyt".
    threat_label: Mapped[str | None] = mapped_column(Text)
    file_type: Mapped[str | None] = mapped_column(Text)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)

    # When anyone first submitted the file. Read against the honeypot's own
    # capture time it says whether this is a new campaign or an old one.
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_analysis_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    vt_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_file_intel_threat_label", "threat_label"),
        # The worker asks for hashes never checked, or unknown ones due a
        # retry; both are answered from this pair.
        Index("ix_file_intel_vt_checked_at", "vt_checked_at"),
        Index("ix_file_intel_known", "known"),
    )
