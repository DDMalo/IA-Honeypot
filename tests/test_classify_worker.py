"""Tests for storing classifier output.

The database tests need PostgreSQL — `behaviours` is a real array column and
the upsert is dialect-specific — so they are skipped unless
`TEST_DATABASE_URL` is set. What is *not* skipped is the selection logic,
which is where the interesting decision lives: which sessions a classifier
still owes an answer for.
"""

from __future__ import annotations

import os
from datetime import UTC, date, datetime, timedelta

import pytest

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Behaviour, Intent, Label, Operator
from honeypot_ai.classify.worker import (
    ClassifyStats,
    DailyShare,
    classify_sessions,
    daily_unmatched,
    pending_sessions,
)
from honeypot_ai.db import SessionLabelRow, SessionRow

TEST_DB = os.getenv("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")

START = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


def label_for(facts: SessionFacts) -> Label:
    return Label(
        session_id=facts.session_id,
        intent=Intent.STAGING,
        behaviours=frozenset({Behaviour.PAYLOAD_DOWNLOAD}),
        operator=Operator.AUTOMATED,
        confidence=0.9,
        notes="fetched and ran a script",
    )


def a_session(session_id: str, minutes_ago: int = 0) -> SessionRow:
    return SessionRow(
        session_id=session_id,
        src_ip="203.0.113.7",
        protocol="ssh",
        started_at=START - timedelta(minutes=minutes_ago),
        authenticated=True,
        command_count=1,
    )


# --- Statistics ------------------------------------------------------------


def test_stats_read_as_a_sentence() -> None:
    assert str(ClassifyStats(pending=3, labelled=3)) == "3 sessions pending, 3 labelled"


def test_a_relabelling_run_says_so() -> None:
    """Otherwise a taxonomy change looks identical to a quiet night."""
    stats = ClassifyStats(pending=50, labelled=50, relabelled=50)
    assert "relabelled for a new taxonomy" in str(stats)


def test_a_classifier_that_gave_up_is_counted_separately_from_one_that_broke() -> None:
    """ "The model declined" and "the call raised" are different findings."""
    stats = ClassifyStats(pending=2, labelled=1, unclassified=1, failed=1)
    assert "1 unclassified" in str(stats)
    assert "1 failed" in str(stats)


# --- Writing labels --------------------------------------------------------


@needs_db
def test_a_label_is_stored_with_its_taxonomy_version(db) -> None:  # type: ignore[no-untyped-def]
    row = a_session("s1")
    db.add(row)
    db.commit()

    stats = classify_sessions(db, label_for, "rules", [row])

    stored = db.get(SessionLabelRow, ("s1", "rules"))
    assert stats.labelled == 1
    assert stored.intent == "staging"
    assert stored.behaviours == ["payload_download"]
    assert stored.operator == "automated"
    assert stored.taxonomy_version == TAXONOMY_VERSION


@needs_db
def test_two_classifiers_label_the_same_session_without_colliding(db) -> None:  # type: ignore[no-untyped-def]
    """The whole reason the key is (session, classifier) and not (session)."""
    row = a_session("s1")
    db.add(row)
    db.commit()

    classify_sessions(db, label_for, "rules", [row])
    classify_sessions(
        db,
        lambda facts: Label(session_id=facts.session_id, intent=Intent.FINGERPRINTING),
        "gemini:test",
        [row],
    )

    assert db.get(SessionLabelRow, ("s1", "rules")).intent == "staging"
    assert db.get(SessionLabelRow, ("s1", "gemini:test")).intent == "fingerprinting"


@needs_db
def test_rerunning_a_classifier_overwrites_only_its_own_answer(db) -> None:  # type: ignore[no-untyped-def]
    row = a_session("s1")
    db.add(row)
    db.commit()

    classify_sessions(db, label_for, "rules", [row])
    classify_sessions(db, label_for, "gemini:test", [row])
    classify_sessions(
        db,
        lambda facts: Label(session_id=facts.session_id, intent=Intent.PERSISTENCE),
        "rules",
        [row],
    )

    assert db.get(SessionLabelRow, ("s1", "rules")).intent == "persistence"
    assert db.get(SessionLabelRow, ("s1", "gemini:test")).intent == "staging"


@needs_db
def test_one_failing_session_does_not_lose_the_rest_of_the_run(db) -> None:  # type: ignore[no-untyped-def]
    """A model call will time out eventually; a run must survive it."""
    rows = [a_session("s1", 2), a_session("s2", 1)]
    db.add_all(rows)
    db.commit()

    def explodes_on_s1(facts: SessionFacts) -> Label:
        if facts.session_id == "s1":
            raise RuntimeError("provider timed out")
        return label_for(facts)

    stats = classify_sessions(db, explodes_on_s1, "rules", rows)

    assert stats.failed == 1
    assert stats.labelled == 1
    assert db.get(SessionLabelRow, ("s1", "rules")) is None
    assert db.get(SessionLabelRow, ("s2", "rules")) is not None


# --- Choosing what to label ------------------------------------------------


@needs_db
def test_a_session_already_labelled_by_this_classifier_is_not_pending(db) -> None:  # type: ignore[no-untyped-def]
    row = a_session("s1")
    db.add(row)
    db.commit()

    assert [r.session_id for r in pending_sessions(db, "rules")] == ["s1"]
    classify_sessions(db, label_for, "rules", [row])
    assert pending_sessions(db, "rules") == []


@needs_db
def test_another_classifier_still_owes_an_answer(db) -> None:  # type: ignore[no-untyped-def]
    row = a_session("s1")
    db.add(row)
    db.commit()
    classify_sessions(db, label_for, "rules", [row])

    assert [r.session_id for r in pending_sessions(db, "gemini:test")] == ["s1"]


@needs_db
def test_a_label_from_an_older_taxonomy_is_pending_again(db) -> None:  # type: ignore[no-untyped-def]
    """The reason the version is stored at all.

    A taxonomy change does not invalidate rows loudly: every one of them is
    still well-formed, still passes every constraint, and now means something
    slightly different. Without this they would sit there indefinitely as a
    silent mixture of two vocabularies.
    """
    row = a_session("s1")
    db.add(row)
    db.commit()
    classify_sessions(db, label_for, "rules", [row])

    stored = db.get(SessionLabelRow, ("s1", "rules"))
    stored.taxonomy_version = TAXONOMY_VERSION - 1
    db.commit()

    assert [r.session_id for r in pending_sessions(db, "rules")] == ["s1"]

    stats = classify_sessions(db, label_for, "rules", pending_sessions(db, "rules"))
    assert stats.relabelled == 1

    # The upsert goes through SQL, so the row held in memory is stale.
    db.expire_all()
    assert db.get(SessionLabelRow, ("s1", "rules")).taxonomy_version == TAXONOMY_VERSION


@needs_db
def test_reclassify_ignores_existing_labels(db) -> None:  # type: ignore[no-untyped-def]
    """For when the rules changed but the vocabulary did not."""
    row = a_session("s1")
    db.add(row)
    db.commit()
    classify_sessions(db, label_for, "rules", [row])

    assert pending_sessions(db, "rules") == []
    assert [r.session_id for r in pending_sessions(db, "rules", reclassify=True)] == ["s1"]


@needs_db
def test_the_newest_sessions_are_labelled_first(db) -> None:  # type: ignore[no-untyped-def]
    """A run cut short by a quota or a closed laptop should leave the traffic
    somebody is about to look at labelled, not the oldest backlog."""
    db.add_all([a_session("old", 600), a_session("recent", 5), a_session("newest", 1)])
    db.commit()

    assert [r.session_id for r in pending_sessions(db, "rules", limit=2)] == [
        "newest",
        "recent",
    ]


@needs_db
def test_deleting_a_session_takes_its_labels_with_it(db) -> None:  # type: ignore[no-untyped-def]
    """Retention deletes sessions; a label for a session nobody kept is litter."""
    row = a_session("s1")
    db.add(row)
    db.commit()
    classify_sessions(db, label_for, "rules", [row])

    db.delete(row)
    db.commit()

    assert db.get(SessionLabelRow, ("s1", "rules")) is None


@pytest.fixture
def db():  # type: ignore[no-untyped-def]
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from honeypot_ai.db import Base

    engine = create_engine(TEST_DB or "", future=True)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    with maker() as session:
        yield session
        session.rollback()
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()


# --- The rehearsal prints tens of thousands of lines ------------------------


class _ClosedPipe:
    """A stdout whose reader has gone away, which is what `| head` leaves."""

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self.writes = 0

    def write(self, text: str) -> int:
        self.writes += 1
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self) -> None:
        return None

    def fileno(self) -> int:
        return self._fd


def test_piping_the_rehearsal_into_head_is_not_an_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """`head` closes the pipe once it has its twenty lines, and the next write
    raises. Printing a traceback over the output makes a normal end to a
    command look exactly like the classifier crashing on session 20."""
    from honeypot_ai.classify.__main__ import _rehearse

    fd = os.open(os.devnull, os.O_WRONLY)
    try:
        pipe = _ClosedPipe(fd)
        monkeypatch.setattr("sys.stdout", pipe)

        assert _rehearse(label_for, [a_session("s1"), a_session("s2")]) == 0
        assert pipe.writes == 1  # stopped at the first refused write
    finally:
        os.close(fd)


# --- Measuring the gap per day ---------------------------------------------


def test_a_quiet_day_is_under_threshold() -> None:
    assert not DailyShare(day=date(2026, 10, 21), unmatched=5, total=8897).over_threshold


def test_the_campaign_day_is_over_threshold() -> None:
    day = DailyShare(day=date(2026, 10, 20), unmatched=2558, total=6484)
    assert day.over_threshold
    assert 0.39 < day.share < 0.40


def test_a_day_with_no_sessions_is_not_a_division_by_zero() -> None:
    assert DailyShare(day=date(2026, 10, 2), unmatched=0, total=0).share == 0.0


def test_averaging_over_the_corpus_would_hide_both_failures() -> None:
    """The reason this is measured per day.

    These are the real figures. Over the corpus they come to 8%, which reads
    as a taxonomy broken for weeks; a year later the same campaign is a
    rounding error and reads as nothing. Per day, one day is 39.5% and the
    rest are under 0.3%, which is what actually happened.
    """
    days = [
        DailyShare(day=date(2026, 10, 19), unmatched=7, total=2584),
        DailyShare(day=date(2026, 10, 20), unmatched=2558, total=6484),
        DailyShare(day=date(2026, 10, 21), unmatched=5, total=8897),
    ]
    pooled = sum(d.unmatched for d in days) / sum(d.total for d in days)

    assert 0.14 < pooled < 0.15  # the pooled figure describes no day at all
    assert [d.over_threshold for d in days] == [False, True, False]


def test_the_line_flags_the_day_it_prints() -> None:
    """Printed into a terminal somebody is skimming."""
    assert "over threshold" in str(DailyShare(date(2026, 10, 20), 2558, 6484))
    assert "over threshold" not in str(DailyShare(date(2026, 10, 21), 5, 8897))


@needs_db
def test_the_audit_counts_unlabelled_sessions_by_day(db) -> None:  # type: ignore[no-untyped-def]
    old = a_session("old", minutes_ago=60 * 26)  # the day before
    today = a_session("today")
    db.add_all([old, today])
    db.commit()

    classify_sessions(
        db,
        lambda facts: Label(
            session_id=facts.session_id,
            intent=Intent.OTHER if facts.session_id == "old" else Intent.STAGING,
        ),
        "rules",
        [old, today],
    )

    days = daily_unmatched(db, "rules")
    assert [(d.unmatched, d.total) for d in days] == [(1, 1), (0, 1)]
