"""Load parsed sessions into PostgreSQL.

The worker reads the log that was synced from the sensor, turns it into
sessions, and writes them to the database. It is designed around one property:
**running it again changes nothing**. Re-reading the whole file is always safe,
so there is no cursor to keep, no position to corrupt, and a failed run is
repaired by simply running it once more.

That matters more than it sounds. The alternative — remembering a byte offset —
breaks the moment Cowrie rotates its log, the sync writes a partial file, or
the worker dies between reading and committing. Idempotency removes that whole
class of bug instead of handling it.

Sessions are written in batches, and sessions already stored unchanged are
skipped, so a run over a file that has barely grown costs almost nothing.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DbSession

from honeypot_ai.db import CommandRow, FileTransferRow, LoginAttemptRow, SessionRow
from honeypot_ai.ingest.parser import ParseStats, parse_file
from honeypot_ai.models import Session

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 500


@dataclass
class LoadStats:
    """What a run did."""

    seen: int = 0
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    parse: ParseStats | None = None

    def __str__(self) -> str:
        return (
            f"{self.seen} sessions seen, {self.inserted} new, "
            f"{self.updated} updated, {self.unchanged} unchanged"
        )


def _batched(items: Iterable[Session], size: int) -> Iterator[list[Session]]:
    """Yield lists of at most `size` sessions."""
    iterator = iter(items)
    while batch := list(islice(iterator, size)):
        yield batch


def _session_values(session: Session, now: datetime) -> dict[str, object]:
    return {
        "session_id": session.session_id,
        "src_ip": session.src_ip or "0.0.0.0",  # noqa: S104 - placeholder, see below
        "src_port": session.src_port,
        "protocol": session.protocol.value if session.protocol else None,
        "sensor": session.sensor,
        "client_version": session.client_version,
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "duration_seconds": session.duration_seconds,
        "authenticated": session.authenticated,
        "command_count": len(session.commands),
        "updated_at": now,
    }


def _fingerprint(session: Session) -> tuple[object, ...]:
    """What has to change for a stored session to be worth rewriting.

    Cowrie only appends to a session, so anything new also moves its last
    event — and therefore `ended_at`. Comparing that, the duration and the
    command count catches every growth without a second query per session.
    """
    return (session.ended_at, session.duration_seconds, len(session.commands))


def load_sessions(
    db: DbSession,
    sessions: Iterable[Session],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> LoadStats:
    """Write sessions to the database, skipping those already stored unchanged.

    Each batch is one transaction. A crash mid-run therefore leaves whole
    batches committed and the rest absent, which the next run completes.
    """
    stats = LoadStats()

    for batch in _batched(sessions, batch_size):
        stats.seen += len(batch)
        now = datetime.now(UTC)

        ids = [session.session_id for session in batch]
        stored = {
            row.session_id: (row.ended_at, row.duration_seconds, row.command_count)
            for row in db.execute(
                select(
                    SessionRow.session_id,
                    SessionRow.ended_at,
                    SessionRow.duration_seconds,
                    SessionRow.command_count,
                ).where(SessionRow.session_id.in_(ids))
            ).all()
        }

        changed = []
        for session in batch:
            previous = stored.get(session.session_id)
            if previous is None:
                stats.inserted += 1
                changed.append(session)
            elif previous != _fingerprint(session):
                stats.updated += 1
                changed.append(session)
            else:
                stats.unchanged += 1

        if changed:
            _write(db, changed, now)

        db.commit()
        logger.info("Batch committed: %s", stats)

    return stats


def _write(db: DbSession, sessions: list[Session], now: datetime) -> None:
    """Upsert the sessions and replace their child rows."""
    rows = [_session_values(session, now) for session in sessions]
    statement = insert(SessionRow).values(rows)
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[SessionRow.session_id],
            set_={
                column: statement.excluded[column] for column in rows[0] if column != "session_id"
            },
        )
    )

    ids = [session.session_id for session in sessions]

    # Child rows are rewritten rather than merged. A session only ever grows,
    # so replacing its contents is both correct and simpler than working out
    # which rows are new — and the unique (session_id, seq) constraint would
    # otherwise reject the overlap.
    for model in (LoginAttemptRow, CommandRow, FileTransferRow):
        db.execute(delete(model).where(model.session_id.in_(ids)))

    logins = [
        {
            "session_id": session.session_id,
            "seq": index,
            "username": attempt.username,
            "password": attempt.password,
            "succeeded": attempt.succeeded,
            "occurred_at": attempt.timestamp,
        }
        for session in sessions
        for index, attempt in enumerate(session.login_attempts)
    ]
    commands = [
        {
            "session_id": session.session_id,
            "seq": index,
            "input": command.input,
            "failed": command.failed,
            "occurred_at": command.timestamp,
        }
        for session in sessions
        for index, command in enumerate(session.commands)
    ]
    transfers = [
        {
            "session_id": session.session_id,
            "seq": index,
            "url": transfer.url,
            "shasum": transfer.shasum,
            "uploaded": transfer.uploaded,
            "occurred_at": transfer.timestamp,
        }
        for session in sessions
        for index, transfer in enumerate(session.file_transfers)
    ]

    if logins:
        db.execute(insert(LoginAttemptRow).values(logins))
    if commands:
        db.execute(insert(CommandRow).values(commands))
    if transfers:
        db.execute(insert(FileTransferRow).values(transfers))


def ingest_file(db: DbSession, path: Path | str, batch_size: int = DEFAULT_BATCH_SIZE) -> LoadStats:
    """Parse one Cowrie log and load it."""
    sessions, parse_stats = parse_file(path)
    logger.info("Parsed %s: %s events, %s skipped", path, parse_stats.events, parse_stats.skipped)

    stats = load_sessions(db, sessions, batch_size)
    stats.parse = parse_stats
    return stats
