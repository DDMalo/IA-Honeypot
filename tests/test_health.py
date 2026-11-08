"""Tests for the freshness check and its notifications.

The checks are judged on the age of the data, so they are tested on
timestamps. The notifications are judged on when they fire — once per change,
never hourly — and on what happens when ntfy is unreachable.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from honeypot_ai.health import __main__ as cli
from honeypot_ai.health.checks import (
    Check,
    check_llm,
    check_rules,
    check_sessions,
    run_checks,
)
from honeypot_ai.health.notify import changes, notify_on_change, read_failing

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)


# --- The checks --------------------------------------------------------------


def test_recent_sessions_pass_and_old_ones_fail() -> None:
    assert check_sessions(NOW - 2 * HOUR, NOW, 6 * HOUR).ok
    assert not check_sessions(NOW - 7 * HOUR, NOW, 6 * HOUR).ok
    assert not check_sessions(None, NOW, 6 * HOUR).ok


def test_unlabelled_sessions_past_the_lag_fail_the_rules_check() -> None:
    assert check_rules(0, None, NOW, 2 * HOUR).ok
    failing = check_rules(72205, NOW - 240 * HOUR, NOW, 2 * HOUR)
    assert not failing.ok
    assert "72205 session(s)" in failing.detail


def test_a_model_that_never_wrote_a_label_fails() -> None:
    assert check_llm(NOW - 20 * HOUR, NOW, 36 * HOUR).ok
    assert not check_llm(NOW - 40 * HOUR, NOW, 36 * HOUR).ok
    assert not check_llm(None, NOW, 36 * HOUR).ok


# --- Notifying once per change ----------------------------------------------


OK = Check("rules", True, "fine")
BROKEN = Check("rules", False, "10 session(s) unlabelled")


def test_only_changes_are_reported() -> None:
    assert changes([BROKEN], set()) == ([BROKEN], [])
    assert changes([BROKEN], {"rules"}) == ([], [])
    assert changes([OK], {"rules"}) == ([], [OK])
    assert changes([OK], set()) == ([], [])


class Recorder:
    def __init__(self, status: int = 200) -> None:
        self.requests: list[httpx.Request] = []
        self.status = status

    def client(self) -> httpx.Client:
        def handle(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(self.status)

        return httpx.Client(transport=httpx.MockTransport(handle))


def test_a_failure_is_sent_once_and_its_recovery_once(tmp_path: Path) -> None:
    state, ntfy = tmp_path / "health.json", Recorder()

    assert notify_on_change([BROKEN], state, topic="t", client=ntfy.client())
    assert not notify_on_change([BROKEN], state, topic="t", client=ntfy.client())
    assert notify_on_change([OK], state, topic="t", client=ntfy.client())

    assert len(ntfy.requests) == 2
    first, second = ntfy.requests
    assert first.url == "https://ntfy.sh/t"
    assert first.headers["Title"] == "Honeypot: rules stopped"
    assert first.headers["Priority"] == "high"
    assert second.headers["Title"] == "Honeypot: rules recovered"


def test_an_unreachable_ntfy_leaves_the_change_pending(tmp_path: Path) -> None:
    """Recording the failure as reported when nobody was told would mean
    nobody is ever told."""
    state = tmp_path / "health.json"
    with pytest.raises(httpx.HTTPStatusError):
        notify_on_change([BROKEN], state, topic="t", client=Recorder(503).client())
    assert read_failing(state) == set()

    assert notify_on_change([BROKEN], state, topic="t", client=Recorder().client())


def test_a_damaged_state_file_counts_as_no_state(tmp_path: Path) -> None:
    state = tmp_path / "health.json"
    state.write_text("not json", encoding="utf-8")
    assert read_failing(state) == set()


def test_notify_refuses_to_run_without_a_topic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    assert cli.main(["--notify"]) == 2


# --- Against the database ----------------------------------------------------

TEST_DB = os.getenv("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")


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


def add(db, session_id: str, *, started: datetime, ingested: datetime) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import SessionRow

    db.add(
        SessionRow(
            session_id=session_id,
            src_ip="203.0.113.7",
            started_at=started,
            ingested_at=ingested,
            authenticated=True,
            command_count=0,
        )
    )
    db.commit()


def label(db, session_id: str, classifier: str, at: datetime) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION
    from honeypot_ai.db import SessionLabelRow

    db.add(
        SessionLabelRow(
            session_id=session_id,
            classifier=classifier,
            intent="fingerprinting",
            behaviours=[],
            operator="unknown",
            taxonomy_version=TAXONOMY_VERSION,
            labelled_at=at,
        )
    )
    db.commit()


@needs_db
def test_a_healthy_pipeline_passes_every_check(db) -> None:  # type: ignore[no-untyped-def]
    add(db, "old", started=NOW - 5 * HOUR, ingested=NOW - 4 * HOUR)
    add(db, "new", started=NOW - HOUR, ingested=NOW - HOUR / 2)  # inside the lag
    label(db, "old", "rules", NOW - 3 * HOUR)
    label(db, "old", "gemini:gemini-3.5-flash-lite", NOW - 10 * HOUR)

    assert all(check.ok for check in run_checks(db, NOW))


@needs_db
def test_a_stopped_rules_timer_is_caught(db) -> None:  # type: ignore[no-untyped-def]
    """The failure that went unnoticed for ten days: sessions keep arriving,
    and nothing labels them."""
    add(db, "a", started=NOW - HOUR, ingested=NOW - 3 * HOUR)
    label(db, "a", "gemini:gemini-3.5-flash-lite", NOW - HOUR)

    checks = {check.name: check for check in run_checks(db, NOW)}
    assert checks["sessions"].ok
    assert not checks["rules"].ok
    assert checks["llm"].ok


@needs_db
def test_another_classifiers_label_does_not_satisfy_the_rules_check(db) -> None:  # type: ignore[no-untyped-def]
    add(db, "a", started=NOW - HOUR, ingested=NOW - 3 * HOUR)
    label(db, "a", "gemini:gemini-3.5-flash-lite", NOW - HOUR)
    checks = {check.name: check for check in run_checks(db, NOW, llm=False)}
    assert not checks["rules"].ok
    assert "llm" not in checks


@needs_db
def test_rule_labels_do_not_count_as_the_models(db) -> None:  # type: ignore[no-untyped-def]
    """The rules write every half hour; if their labels counted, a dead model
    timer would never show."""
    add(db, "a", started=NOW - HOUR, ingested=NOW - 3 * HOUR)
    label(db, "a", "rules", NOW - HOUR)
    checks = {check.name: check for check in run_checks(db, NOW)}
    assert not checks["llm"].ok
