"""Tests for drawing the evaluation sample.

What matters is that the sample is reproducible, covers every class well
enough to measure it, and never spends a label twice on the same behaviour.
"""

from __future__ import annotations

import itertools
import os
from collections import Counter
from datetime import UTC, datetime

import pytest

from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Intent
from honeypot_ai.label.sample import Candidate, DrawnBy, choose


def pool() -> list[Candidate]:
    """Shaped like the real corpus: one class dominates, others are rare."""
    candidates = [
        Candidate(f"fp{n:04d}", Intent.FINGERPRINTING, sessions=50, representative=f"f{n}")
        for n in range(200)
    ]
    candidates += [
        Candidate(f"st{n:04d}", Intent.STAGING, sessions=5, representative=f"s{n}")
        for n in range(30)
    ]
    candidates += [
        Candidate(f"pe{n:04d}", Intent.PERSISTENCE, sessions=2, representative=f"p{n}")
        for n in range(4)
    ]
    return candidates


def test_the_same_seed_draws_the_same_sample() -> None:
    first = choose(pool(), per_class=10, uniform=20, seed=7)
    second = choose(pool(), per_class=10, uniform=20, seed=7)
    assert first == second


def test_a_different_seed_draws_a_different_sample() -> None:
    assert choose(pool(), per_class=10, uniform=20, seed=1) != choose(
        pool(), per_class=10, uniform=20, seed=2
    )


def test_the_order_rows_arrive_in_does_not_change_the_sample() -> None:
    """The database returns rows in whatever order it likes."""
    forward = choose(pool(), per_class=10, uniform=20, seed=7)
    backward = choose(list(reversed(pool())), per_class=10, uniform=20, seed=7)
    assert forward == backward


def test_every_class_reaches_its_floor_when_it_can() -> None:
    """The reason the stratified part exists: a random draw over sessions
    would contain almost no persistence, and per-class precision would rest
    on one or two labels."""
    picked = choose(pool(), per_class=10, uniform=20, seed=7)
    by_class = Counter(candidate.stratum for candidate, _ in picked)

    assert by_class[Intent.FINGERPRINTING] >= 10
    assert by_class[Intent.STAGING] >= 10


def test_a_class_with_fewer_candidates_than_the_floor_gives_all_it_has() -> None:
    picked = choose(pool(), per_class=10, uniform=0, seed=7)
    persistence = [c for c, _ in picked if c.stratum is Intent.PERSISTENCE]
    assert len(persistence) == 4


def test_no_behaviour_is_labelled_twice() -> None:
    candidates = [
        *pool(),
        # The rules called one sequence two different things.
        Candidate("dup0", Intent.STAGING, sessions=500, representative="d1"),
        Candidate("dup0", Intent.PERSISTENCE, sessions=500, representative="d2"),
    ]
    picked = choose(candidates, per_class=40, uniform=100, seed=7)
    fingerprints = [candidate.fingerprint for candidate, _ in picked]
    assert len(fingerprints) == len(set(fingerprints))


def test_the_uniform_part_favours_what_actually_arrives() -> None:
    """Drawn in proportion to sessions, so it describes the real population."""
    candidates = [
        Candidate("heavy", Intent.STAGING, sessions=100_000, representative="h"),
        *(
            Candidate(f"light{n}", Intent.STAGING, sessions=1, representative=f"l{n}")
            for n in range(500)
        ),
    ]
    hits = sum(
        any(c.fingerprint == "heavy" for c, _ in choose(candidates, per_class=0, uniform=5, seed=s))
        for s in range(50)
    )
    assert hits == 50


def test_each_item_records_which_part_drew_it() -> None:
    """The evaluation keeps the two apart: only the uniform part describes the
    population, and only the stratified part guarantees coverage."""
    picked = choose(pool(), per_class=10, uniform=20, seed=7)
    parts = Counter(drawn_by for _, drawn_by in picked)
    assert parts[DrawnBy.UNIFORM] == 20
    assert parts[DrawnBy.STRATUM] > 0


def test_the_sample_is_shuffled_so_a_class_does_not_arrive_in_a_run() -> None:
    picked = choose(pool(), per_class=10, uniform=0, seed=7)
    strata = [candidate.stratum for candidate, _ in picked]
    longest = max(sum(1 for _ in group) for _, group in itertools.groupby(strata))
    assert longest < 10


# --- Against a real database -----------------------------------------------

TEST_DB = os.getenv("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")


@needs_db
def test_identical_sessions_become_one_candidate_with_their_count(db) -> None:  # type: ignore[no-untyped-def]
    """The 13 October campaign was 2,555 copies of one command. One item."""
    from honeypot_ai.db import CommandRow, SessionLabelRow, SessionRow
    from honeypot_ai.label.sample import load_candidates

    at = datetime(2026, 10, 20, tzinfo=UTC)
    for n in range(5):
        db.add(SessionRow(session_id=f"same{n}", src_ip="203.0.113.1", started_at=at))
        db.add(
            CommandRow(session_id=f"same{n}", seq=0, input="uname -a", failed=False, occurred_at=at)
        )
    db.add(SessionRow(session_id="other", src_ip="203.0.113.2", started_at=at))
    db.add(CommandRow(session_id="other", seq=0, input="nproc", failed=False, occurred_at=at))
    db.flush()
    for session_id in [*(f"same{n}" for n in range(5)), "other"]:
        db.add(
            SessionLabelRow(
                session_id=session_id,
                classifier="rules",
                intent="fingerprinting",
                behaviours=[],
                operator="automated",
                confidence=1.0,
                taxonomy_version=TAXONOMY_VERSION,
            )
        )
    db.commit()

    weights = sorted(candidate.sessions for candidate in load_candidates(db))
    assert weights == [1, 5]


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
