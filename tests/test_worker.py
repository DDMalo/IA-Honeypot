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

from honeypot_ai.ingest.worker import (
    MAX_BIND_PARAMETERS,
    _batched,
    _fingerprint,
    log_files,
    rows_per_statement,
)
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


# --- The bind-parameter limit ----------------------------------------------
#
# Ingestion batched five hundred sessions per transaction and then wrote every
# child row of those sessions in one INSERT. Sessions bound the transaction;
# nothing bound the statement. On 27 October a backlog of scripted sessions put
# 15,090 commands in one batch — 75,450 bind parameters against a protocol
# limit of 65,535 — and the whole run failed rather than the batch.


def test_a_statement_never_exceeds_the_protocol_limit() -> None:
    for columns in range(1, 40):
        assert rows_per_statement(columns) * columns <= MAX_BIND_PARAMETERS


def test_a_row_wider_than_the_limit_still_yields_one_row() -> None:
    """Dividing to zero would loop forever rather than fail."""
    assert rows_per_statement(MAX_BIND_PARAMETERS * 2) == 1
    assert rows_per_statement(0) >= 1


def test_the_batch_that_broke_it_now_splits() -> None:
    """The real numbers from the failure."""
    assert 15_090 * 5 > MAX_BIND_PARAMETERS
    assert rows_per_statement(5) < 15_090


@needs_db
def test_a_batch_of_sessions_too_large_for_one_statement_is_written(db) -> None:  # type: ignore[no-untyped-def]
    """The regression, end to end.

    Two sessions of 10,000 commands is 100,000 bind parameters in a single
    INSERT. Before the fix this raised and nothing at all was ingested.
    """
    from sqlalchemy import func, select

    from honeypot_ai.db import CommandRow
    from honeypot_ai.ingest.worker import load_sessions

    sessions = [_session("big1", commands=10_000), _session("big2", commands=10_000)]
    stats = load_sessions(db, sessions, batch_size=500)

    stored = db.execute(
        select(func.count())
        .select_from(CommandRow)
        .where(CommandRow.session_id.in_(["big1", "big2"]))
    ).scalar_one()

    assert stats.inserted == 2
    assert stored == 20_000


# --- Rotated logs ----------------------------------------------------------
#
# Cowrie rotates cowrie.json at midnight. Ingestion was pointed at the live
# file alone, which on a machine that runs continuously reads everything and on
# one that is switched on to work reads only what happened since the last
# midnight. Twenty-six days of rotated logs sat synced and unread on disk.


def _logs(tmp_path: Path, *names: str) -> Path:
    for name in names:
        (tmp_path / name).write_text("")
    return tmp_path


def test_every_rotated_log_is_read_not_just_the_live_one(tmp_path: Path) -> None:
    found = log_files(
        _logs(tmp_path, "cowrie.json", "cowrie.json.2026-10-26", "cowrie.json.2026-10-25")
    )
    assert [p.name for p in found] == [
        "cowrie.json.2026-10-25",
        "cowrie.json.2026-10-26",
        "cowrie.json",
    ]


def test_the_live_log_is_read_last(tmp_path: Path) -> None:
    """It holds the newest half of any session that straddled a rotation."""
    found = log_files(_logs(tmp_path, "cowrie.json", "cowrie.json.2026-09-30"))
    assert found[-1].name == "cowrie.json"


def test_a_directory_with_only_rotated_logs_still_works(tmp_path: Path) -> None:
    found = log_files(_logs(tmp_path, "cowrie.json.2026-10-01"))
    assert [p.name for p in found] == ["cowrie.json.2026-10-01"]


def test_a_single_file_is_still_accepted(tmp_path: Path) -> None:
    log = tmp_path / "cowrie.json"
    log.write_text("")
    assert log_files(log) == [log]


def test_unrelated_files_are_ignored(tmp_path: Path) -> None:
    found = log_files(_logs(tmp_path, "cowrie.json", "cowrie.log", ".sync.lock", "notes.txt"))
    assert [p.name for p in found] == ["cowrie.json"]


@needs_db
def test_a_session_split_across_a_rotation_keeps_its_larger_half(db) -> None:  # type: ignore[no-untyped-def]
    """Neither half is the whole session, and the second must not replace the
    first just for arriving later. Cowrie only appends, so a version with
    fewer commands than the stored one cannot be the same session having
    shrunk — it is the other side of a rotation."""
    from honeypot_ai.db import SessionRow
    from honeypot_ai.ingest.worker import load_sessions

    load_sessions(db, [_session("split", commands=9)])
    stats = load_sessions(db, [_session("split", commands=2)])

    db.expire_all()
    assert stats.truncated == 1
    assert stats.updated == 0
    assert db.get(SessionRow, "split").command_count == 9


@needs_db
def test_a_session_that_grew_is_still_rewritten(db) -> None:  # type: ignore[no-untyped-def]
    """The guard must not block the ordinary case it sits next to."""
    from honeypot_ai.db import SessionRow
    from honeypot_ai.ingest.worker import load_sessions

    load_sessions(db, [_session("grows", commands=2)])
    stats = load_sessions(db, [_session("grows", commands=9)])

    db.expire_all()
    assert stats.updated == 1
    assert stats.truncated == 0
    assert db.get(SessionRow, "grows").command_count == 9
