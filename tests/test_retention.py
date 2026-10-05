"""Tests for the retention policy.

Retention deletes data irreversibly, so these tests check the two things that
would actually hurt if they were wrong: that the window is respected, and that
deleting a session takes everything attached to it.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

TEST_DB = os.getenv("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")


@pytest.fixture
def db():  # type: ignore[no-untyped-def]
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from honeypot_ai.db import Base

    engine = create_engine(TEST_DB or "", future=True)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    with maker() as session:
        yield session
        session.rollback()
        session.execute(text("TRUNCATE sessions, ip_intel CASCADE"))
        session.commit()


def _add_session(db, session_id: str, days_ago: int) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import CommandRow, LoginAttemptRow, SessionRow

    when = datetime.now(UTC) - timedelta(days=days_ago)
    db.add(
        SessionRow(
            session_id=session_id,
            src_ip="203.0.113.10",
            started_at=when,
            ended_at=when,
            command_count=1,
        )
    )
    db.add(
        LoginAttemptRow(
            session_id=session_id,
            seq=0,
            username="root",
            password="x",  # noqa: S106
            succeeded=True,
            occurred_at=when,
        )
    )
    db.add(CommandRow(session_id=session_id, seq=0, input="id", failed=False, occurred_at=when))
    db.commit()


@needs_db
def test_only_sessions_past_the_window_are_deleted(db) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import SessionRow
    from honeypot_ai.retention import apply_retention

    _add_session(db, "old", days_ago=400)
    _add_session(db, "recent", days_ago=10)

    stats = apply_retention(db, days=365)

    assert stats.sessions_deleted == 1
    assert {row.session_id for row in db.query(SessionRow).all()} == {"recent"}


@needs_db
def test_deleting_a_session_takes_its_children(db) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import CommandRow, LoginAttemptRow
    from honeypot_ai.retention import apply_retention

    _add_session(db, "old", days_ago=400)
    assert db.query(CommandRow).count() == 1

    apply_retention(db, days=365)

    assert db.query(CommandRow).count() == 0
    assert db.query(LoginAttemptRow).count() == 0


@needs_db
def test_addresses_nobody_refers_to_are_forgotten(db) -> None:  # type: ignore[no-untyped-def]
    """Keeping the list of who attacked after deleting the attacks defeats the point."""
    from honeypot_ai.db import IpIntelRow
    from honeypot_ai.retention import apply_retention

    _add_session(db, "old", days_ago=400)
    db.add(IpIntelRow(ip="203.0.113.10", country_code="RO", geo_checked_at=datetime.now(UTC)))
    db.commit()

    stats = apply_retention(db, days=365)

    assert stats.addresses_deleted == 1
    assert db.query(IpIntelRow).count() == 0


@needs_db
def test_an_address_still_in_use_is_kept(db) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import IpIntelRow
    from honeypot_ai.retention import apply_retention

    _add_session(db, "recent", days_ago=10)
    db.add(IpIntelRow(ip="203.0.113.10", country_code="RO", geo_checked_at=datetime.now(UTC)))
    db.commit()

    apply_retention(db, days=365)

    assert db.query(IpIntelRow).count() == 1


@needs_db
def test_a_dry_run_deletes_nothing(db) -> None:  # type: ignore[no-untyped-def]
    """Deleting the wrong thing is unrecoverable, so the rehearsal must be real."""
    from honeypot_ai.db import SessionRow
    from honeypot_ai.retention import apply_retention

    _add_session(db, "old", days_ago=400)

    stats = apply_retention(db, days=365, dry_run=True)

    assert stats.sessions_deleted == 1
    assert db.query(SessionRow).count() == 1
