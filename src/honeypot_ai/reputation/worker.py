"""Decide which addresses to check, and store what comes back.

The selection rule is the whole point of this module. Checking every address
every run would spend the daily allowance in minutes and tell us nothing new,
so an address is checked when it has never been checked, or when the last
check has gone stale. Stale matters here in a way it does not for geolocation:
an address that was quiet last month may have been reported a thousand times
since.

Addresses are then ordered by how much traffic they account for, so if the
budget runs out it runs out on the long tail of one-session scanners rather
than on the bot that has been hammering the sensor all week.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DbSession

from honeypot_ai.db import IpIntelRow, SessionRow
from honeypot_ai.reputation.abuseipdb import QuotaExhausted, Reputer

logger = logging.getLogger(__name__)

#: The free tier allows 1,000 checks a day. Stopping short of it leaves room
#: for a manual lookup while investigating something.
DEFAULT_DAILY_LIMIT = 900

#: How long a result is trusted before it is checked again.
DEFAULT_MAX_AGE_DAYS = 14

DEFAULT_BATCH_SIZE = 50


@dataclass
class ReputationStats:
    """What a run did."""

    pending: int = 0
    checked: int = 0
    unknown: int = 0
    reported: int = 0
    stopped_early: bool = False

    def __str__(self) -> str:
        tail = " (stopped early: quota)" if self.stopped_early else ""
        return (
            f"{self.pending} addresses pending, {self.checked} checked, "
            f"{self.reported} with reports, {self.unknown} unknown{tail}"
        )


def pending_addresses(
    db: DbSession,
    limit: int | None = DEFAULT_DAILY_LIMIT,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
) -> list[str]:
    """Addresses that have never been checked, or whose check has gone stale.

    Busiest first: the budget should be spent on the addresses the data is
    actually about.
    """
    cutoff = datetime.now(UTC) - timedelta(days=max_age_days)

    statement = (
        select(SessionRow.src_ip, func.count().label("sessions"))
        .select_from(SessionRow)
        .outerjoin(IpIntelRow, IpIntelRow.ip == SessionRow.src_ip)
        .where(
            or_(
                IpIntelRow.abuse_checked_at.is_(None),
                IpIntelRow.abuse_checked_at < cutoff,
            )
        )
        .group_by(SessionRow.src_ip)
        .order_by(func.count().desc())
    )
    if limit is not None:
        statement = statement.limit(limit)

    return [str(row[0]) for row in db.execute(statement).all()]


def check_addresses(
    db: DbSession,
    reputer: Reputer,
    addresses: list[str],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> ReputationStats:
    """Look each address up and store the result.

    Written in small batches rather than one transaction at the end: an
    interrupted run — a quota limit, a reboot, Ctrl-C — keeps everything it had
    already paid for.
    """
    stats = ReputationStats(pending=len(addresses))
    rows: list[dict[str, object]] = []

    for address in addresses:
        try:
            info = reputer.lookup(address)
        except QuotaExhausted:
            logger.info("Quota reached after %d addresses; stopping", stats.checked)
            stats.stopped_early = True
            break

        stats.checked += 1
        if info.empty:
            stats.unknown += 1
        elif info.abuse_score:
            stats.reported += 1

        rows.append(
            {
                "ip": address,
                "abuse_score": info.abuse_score,
                "abuse_reports": info.total_reports,
                "abuse_reporters": info.distinct_reporters,
                "abuse_last_reported_at": info.last_reported_at,
                "abuse_isp": info.isp,
                "abuse_usage_type": info.usage_type,
                "abuse_domain": info.domain,
                "abuse_is_tor": info.is_tor,
                # Stamped even when nothing came back, so a dud lookup is not
                # retried on every run for the rest of the window.
                "abuse_checked_at": datetime.now(UTC),
            }
        )

        if len(rows) >= batch_size:
            _write(db, rows)
            db.commit()
            rows = []

    if rows:
        _write(db, rows)
    db.commit()

    return stats


def _write(db: DbSession, rows: list[dict[str, object]]) -> None:
    """Upsert the checked addresses.

    An address may have no `ip_intel` row yet — reputation can run before
    geolocation — so this inserts as readily as it updates, and touches only
    the reputation columns either way.
    """
    statement = insert(IpIntelRow).values(rows)
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[IpIntelRow.ip],
            set_={column: statement.excluded[column] for column in rows[0] if column != "ip"},
        )
    )
    logger.info("Wrote reputation for %d addresses", len(rows))


def check_pending(
    db: DbSession,
    reputer: Reputer,
    limit: int | None = DEFAULT_DAILY_LIMIT,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> ReputationStats:
    """Check every address that is due."""
    addresses = pending_addresses(db, limit, max_age_days)
    logger.info("%d addresses to check", len(addresses))
    return check_addresses(db, reputer, addresses, batch_size)
