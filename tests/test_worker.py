"""Tests for the ingestion worker.

The tests that need a real PostgreSQL are skipped unless `TEST_DATABASE_URL`
points at a throwaway database, so CI stays free of infrastructure. Run them
locally with, for example:

    TEST_DATABASE_URL=postgresql+psycopg://honeypot:pw@localhost:5432/honeypot_test pytest

Everything that can be checked without a database is checked without one.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from honeypot_ai.ingest.worker import _batched, _fingerprint
from honeypot_ai.models import Command, Session

TS = datetime(2026, 9, 30, 21, 33, 32, tzinfo=UTC)
FIXTURES = Path(__file__).parent / "fixtures"


def _session(session_id: str, commands: int = 0, ended: datetime | None = None) -> Session:
    return Session(
        session_id=session_id,
        src_ip="203.0.113.1",
        started_at=TS,
        ended_at=ended,
        commands=tuple(
            Command(input=f"cmd{i}", failed=False, timestamp=TS) for i in range(commands)
        ),
    )


def test_batching_splits_and_keeps_everything() -> None:
    sessions = [_session(str(i)) for i in range(7)]
    batches = list(_batched(sessions, 3))

    assert [len(batch) for batch in batches] == [3, 3, 1]
    assert [s.session_id for batch in batches for s in batch] == [str(i) for i in range(7)]


def test_batching_an_empty_input_yields_nothing() -> None:
    assert list(_batched([], 10)) == []


def test_fingerprint_is_stable_for_an_unchanged_session() -> None:
    assert _fingerprint(_session("a", commands=2)) == _fingerprint(_session("a", commands=2))


def test_fingerprint_changes_when_a_session_grows() -> None:
    """A session that gained a command must be rewritten, not skipped."""
    assert _fingerprint(_session("a", commands=2)) != _fingerprint(_session("a", commands=3))


def test_fingerprint_changes_when_a_session_ends() -> None:
    """Cowrie only appends, so anything new also moves the last event."""
    before = _session("a", commands=1)
    after = _session("a", commands=1, ended=datetime(2026, 9, 30, 21, 40, tzinfo=UTC))
    assert _fingerprint(before) != _fingerprint(after)


# --- Tests that need a database ---------------------------------------------

TEST_DB = os.getenv("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")


@pytest.fixture
def db():  # type: ignore[no-untyped-def]
    """A clean database session, rolled back to empty tables afterwards."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from honeypot_ai.db import Base

    engine = create_engine(TEST_DB or "", future=True)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    with maker() as session:
        yield session
        session.rollback()
        session.execute(text("TRUNCATE sessions CASCADE"))
        session.commit()


@needs_db
def test_ingesting_the_sample_stores_every_session(db) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import SessionRow
    from honeypot_ai.ingest.worker import ingest_file

    stats = ingest_file(db, FIXTURES / "cowrie-sample.json")

    assert (stats.seen, stats.inserted, stats.updated, stats.unchanged) == (3, 3, 0, 0)
    assert db.query(SessionRow).count() == 3


@needs_db
def test_ingesting_twice_changes_nothing(db) -> None:  # type: ignore[no-untyped-def]
    """The property the whole design rests on: re-running is safe and cheap."""
    from honeypot_ai.db import LoginAttemptRow
    from honeypot_ai.ingest.worker import ingest_file

    ingest_file(db, FIXTURES / "cowrie-sample.json")
    logins_after_first = db.query(LoginAttemptRow).count()

    stats = ingest_file(db, FIXTURES / "cowrie-sample.json")

    assert (stats.inserted, stats.updated, stats.unchanged) == (0, 0, 3)
    assert db.query(LoginAttemptRow).count() == logins_after_first


@needs_db
def test_deleting_a_session_removes_its_children(db) -> None:  # type: ignore[no-untyped-def]
    """Retention has to be one DELETE, not a script."""
    from honeypot_ai.db import CommandRow, SessionRow
    from honeypot_ai.ingest.worker import ingest_file

    ingest_file(db, FIXTURES / "cowrie-sample.json")
    assert db.query(CommandRow).count() > 0

    db.query(SessionRow).delete()
    db.commit()

    assert db.query(CommandRow).count() == 0
