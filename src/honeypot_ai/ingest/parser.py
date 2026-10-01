"""Parse `cowrie.json` into sessions.

Cowrie writes one JSON object per line. The file is append-only and grows for
as long as the honeypot runs, so it is read as a stream: lines are consumed one
at a time and never held in memory as a whole.

Robustness matters more than strictness here. The sensor is a machine that
hostile strangers interact with, and its log is written while it is under
attack: lines get truncated when the process restarts mid-write, unfamiliar
event types appear after an upgrade, and sessions are left open when a
connection drops. None of that may stop the rest of the file being ingested.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from honeypot_ai.models import (
    Command,
    CowrieEvent,
    EventId,
    FileTransfer,
    LoginAttempt,
    Protocol,
    Session,
)

logger = logging.getLogger(__name__)


@dataclass
class ParseStats:
    """What happened while reading a log.

    Counting what was skipped, rather than silently dropping it, is what makes
    a quiet failure visible: a sudden rise in `malformed` means the sensor is
    writing something unexpected and the pipeline is losing data.
    """

    lines: int = 0
    events: int = 0
    malformed: int = 0
    invalid: int = 0

    @property
    def skipped(self) -> int:
        return self.malformed + self.invalid


@dataclass
class _SessionBuilder:
    """Mutable accumulator for one session, frozen into a `Session` at the end."""

    session_id: str
    src_ip: str = ""
    src_port: int | None = None
    protocol: Protocol | None = None
    sensor: str = ""
    client_version: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    ended_at: datetime | None = None
    duration_seconds: float | None = None
    logins: list[LoginAttempt] = field(default_factory=list)
    commands: list[Command] = field(default_factory=list)
    transfers: list[FileTransfer] = field(default_factory=list)


def iter_events(lines: Iterable[str], stats: ParseStats | None = None) -> Iterator[CowrieEvent]:
    """Yield one `CowrieEvent` per valid line, skipping the rest.

    A line is skipped when it is not valid JSON (usually a truncated write) or
    when it lacks the fields every event must have. Both are counted.
    """
    counters = stats if stats is not None else ParseStats()

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        counters.lines += 1

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            counters.malformed += 1
            logger.debug("Skipping malformed line %d", counters.lines)
            continue

        if not isinstance(payload, dict):
            counters.malformed += 1
            continue

        try:
            event = CowrieEvent.model_validate(payload)
        except ValueError:
            counters.invalid += 1
            logger.debug("Skipping invalid event on line %d", counters.lines)
            continue

        counters.events += 1
        yield event


def build_sessions(events: Iterable[CowrieEvent]) -> list[Session]:
    """Group events into sessions, ordered by when each session started.

    Events are grouped by Cowrie's session id rather than by source address:
    one address often opens many connections, and each is its own story.

    A session is emitted even when its `connect` or `closed` event is missing.
    Connections are dropped mid-flight all the time, and a session that was cut
    short still says something about the attacker.
    """
    builders: dict[str, _SessionBuilder] = {}
    order: defaultdict[str, int] = defaultdict(int)

    for index, event in enumerate(events):
        builder = builders.get(event.session)
        if builder is None:
            builder = _SessionBuilder(session_id=event.session)
            builders[event.session] = builder
            order[event.session] = index

        _apply(builder, event)

    sessions = [_freeze(builder) for builder in builders.values()]
    sessions.sort(key=lambda session: (session.started_at, session.session_id))
    return sessions


def parse_file(path: Path | str) -> tuple[list[Session], ParseStats]:
    """Read a `cowrie.json` file and return its sessions, plus what was skipped."""
    stats = ParseStats()
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        sessions = build_sessions(iter_events(handle, stats))
    return sessions, stats


def _apply(builder: _SessionBuilder, event: CowrieEvent) -> None:
    """Fold a single event into the session being assembled."""
    # Identity fields can arrive on any event; the first non-empty value wins,
    # because `connect` is not guaranteed to be the first line seen.
    if not builder.src_ip and event.src_ip:
        builder.src_ip = event.src_ip
    if builder.src_port is None and event.src_port is not None:
        builder.src_port = event.src_port
    if builder.protocol is None and event.protocol is not None:
        builder.protocol = event.protocol
    if not builder.sensor and event.sensor:
        builder.sensor = event.sensor

    timestamp = event.timestamp
    if builder.first_seen is None or timestamp < builder.first_seen:
        builder.first_seen = timestamp
    if builder.last_seen is None or timestamp > builder.last_seen:
        builder.last_seen = timestamp

    match event.known_event:
        case EventId.CLIENT_VERSION:
            builder.client_version = event.version
        case EventId.LOGIN_SUCCESS | EventId.LOGIN_FAILED:
            builder.logins.append(
                LoginAttempt(
                    username=event.username or "",
                    password=event.password or "",
                    succeeded=event.known_event is EventId.LOGIN_SUCCESS,
                    timestamp=timestamp,
                )
            )
        case EventId.COMMAND_INPUT | EventId.COMMAND_FAILED:
            builder.commands.append(
                Command(
                    input=event.input or "",
                    failed=event.known_event is EventId.COMMAND_FAILED,
                    timestamp=timestamp,
                )
            )
        case EventId.FILE_DOWNLOAD | EventId.FILE_UPLOAD:
            builder.transfers.append(
                FileTransfer(
                    url=event.url,
                    shasum=event.shasum,
                    uploaded=event.known_event is EventId.FILE_UPLOAD,
                    timestamp=timestamp,
                )
            )
        case EventId.SESSION_CLOSED:
            builder.ended_at = timestamp
            builder.duration_seconds = event.duration
        case _:
            pass


def _freeze(builder: _SessionBuilder) -> Session:
    """Turn the accumulator into the immutable session."""
    started_at = builder.first_seen
    if started_at is None:  # pragma: no cover - a builder always sees one event
        raise ValueError(f"session {builder.session_id} has no events")

    ended_at = builder.ended_at or builder.last_seen
    duration = builder.duration_seconds
    if duration is None and ended_at is not None:
        duration = (ended_at - started_at).total_seconds()

    return Session(
        session_id=builder.session_id,
        src_ip=builder.src_ip,
        src_port=builder.src_port,
        protocol=builder.protocol,
        sensor=builder.sensor,
        client_version=builder.client_version,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=duration,
        login_attempts=tuple(builder.logins),
        commands=tuple(builder.commands),
        file_transfers=tuple(builder.transfers),
    )
