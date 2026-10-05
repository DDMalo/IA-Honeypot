"""Database retention.

Two rules, both deliberately simple enough to explain to someone who is not a
programmer — which is the test a privacy measure has to pass:

1. A session older than the retention window is deleted, along with its
   credentials, commands and file transfers.
2. An address nobody references any more is forgotten, and so is the report
   on a file hash nothing refers to any more.

Raw log files and captured samples are pruned separately, on the machines that
hold them (see the deployment scripts); this module governs the database.

A possible refinement, not implemented: instead of deleting old sessions,
truncate their address to a /24 and keep the rest. That would preserve the
long-term trend analysis while removing the identifying part. It is recorded
here because the decision is a trade-off, not an oversight — deleting is
simpler to reason about and simpler to verify, which for a first version
matters more than squeezing out extra history.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.orm import Session as DbSession

from honeypot_ai.db import FileIntelRow, FileTransferRow, IpIntelRow, SessionRow

logger = logging.getLogger(__name__)

DEFAULT_SESSION_DAYS = 365


@dataclass
class RetentionStats:
    """What a run removed."""

    cutoff: datetime
    sessions_deleted: int = 0
    addresses_deleted: int = 0
    hashes_deleted: int = 0

    def __str__(self) -> str:
        return (
            f"Deleted {self.sessions_deleted} sessions started before "
            f"{self.cutoff:%Y-%m-%d}, {self.addresses_deleted} unreferenced addresses "
            f"and {self.hashes_deleted} unreferenced file reports"
        )


def prune_sessions(db: DbSession, cutoff: datetime) -> int:
    """Delete sessions that started before `cutoff`.

    Child rows go with them: the foreign keys cascade, which is exactly why
    the schema was built that way.
    """
    result = db.execute(delete(SessionRow).where(SessionRow.started_at < cutoff))
    deleted = cast("CursorResult[Any]", result).rowcount or 0
    logger.info("Deleted %d sessions started before %s", deleted, cutoff.isoformat())
    return deleted


def prune_orphaned_intel(db: DbSession) -> int:
    """Forget addresses no session refers to any more.

    Keeping them would quietly defeat the point: the sessions would be gone
    while the list of who attacked remained.
    """
    referenced = select(SessionRow.src_ip).distinct()
    result = db.execute(delete(IpIntelRow).where(IpIntelRow.ip.not_in(referenced)))
    deleted = cast("CursorResult[Any]", result).rowcount or 0
    logger.info("Deleted %d unreferenced addresses", deleted)
    return deleted


def prune_orphaned_file_intel(db: DbSession) -> int:
    """Forget reports on hashes no transfer refers to any more.

    A hash is not personal data, so this is housekeeping rather than privacy:
    without it the table would grow forever, holding reports on files whose
    sessions were deleted a year ago.
    """
    referenced = select(FileTransferRow.shasum).where(FileTransferRow.shasum.is_not(None))
    result = db.execute(delete(FileIntelRow).where(FileIntelRow.sha256.not_in(referenced)))
    deleted = cast("CursorResult[Any]", result).rowcount or 0
    logger.info("Deleted %d unreferenced file reports", deleted)
    return deleted


def apply_retention(
    db: DbSession, days: int = DEFAULT_SESSION_DAYS, dry_run: bool = False
) -> RetentionStats:
    """Enforce the policy.

    `dry_run` reports what would go without touching anything — worth having,
    because a retention job that deletes the wrong thing is not recoverable.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    stats = RetentionStats(cutoff=cutoff)

    if dry_run:
        stats.sessions_deleted = (
            db.execute(
                select(func.count()).select_from(SessionRow).where(SessionRow.started_at < cutoff)
            ).scalar_one()
            or 0
        )
        referenced = select(SessionRow.src_ip).distinct()
        stats.addresses_deleted = (
            db.execute(
                select(func.count()).select_from(IpIntelRow).where(IpIntelRow.ip.not_in(referenced))
            ).scalar_one()
            or 0
        )
        referenced_hashes = select(FileTransferRow.shasum).where(
            FileTransferRow.shasum.is_not(None)
        )
        stats.hashes_deleted = (
            db.execute(
                select(func.count())
                .select_from(FileIntelRow)
                .where(FileIntelRow.sha256.not_in(referenced_hashes))
            ).scalar_one()
            or 0
        )
        db.rollback()
        return stats

    stats.sessions_deleted = prune_sessions(db, cutoff)
    stats.addresses_deleted = prune_orphaned_intel(db)
    stats.hashes_deleted = prune_orphaned_file_intel(db)
    db.commit()
    return stats
