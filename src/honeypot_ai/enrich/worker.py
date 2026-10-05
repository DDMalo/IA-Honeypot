"""Fill in what is known about the addresses seen by the honeypot.

Enrichment is kept apart from ingestion on purpose. Ingestion must be fast and
must never depend on anything outside the machine; enrichment reads databases,
and will later call rate-limited APIs. Separating them means a lookup problem
delays enrichment without ever blocking the capture of new sessions.

Work is done per *address*, not per session. A single bot accounts for hundreds
of sessions, so resolving it once is the difference between a handful of
lookups and tens of thousands.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DbSession

from honeypot_ai.db import IpIntelRow, SessionRow
from honeypot_ai.enrich.geoip import Locator

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 1000


@dataclass
class EnrichStats:
    """What a run did."""

    pending: int = 0
    resolved: int = 0
    unknown: int = 0

    def __str__(self) -> str:
        return (
            f"{self.pending} addresses pending, {self.resolved} resolved, "
            f"{self.unknown} not in the databases"
        )


def pending_addresses(db: DbSession, limit: int | None = None) -> list[str]:
    """Addresses seen in sessions that have never been looked up.

    Re-checking an address already resolved would waste the lookup budget, so
    anything with a `geo_checked_at` is left alone — including addresses the
    databases did not recognise, which is why that timestamp is set either way.
    """
    known = select(IpIntelRow.ip).where(IpIntelRow.geo_checked_at.is_not(None))
    statement = select(SessionRow.src_ip).distinct().where(SessionRow.src_ip.not_in(known))
    if limit is not None:
        statement = statement.limit(limit)

    return [str(row[0]) for row in db.execute(statement).all()]


def enrich_addresses(
    db: DbSession,
    locator: Locator,
    addresses: list[str],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> EnrichStats:
    """Look each address up and store the result."""
    stats = EnrichStats(pending=len(addresses))
    rows: list[dict[str, object]] = []

    for address in addresses:
        info = locator.lookup(address)
        if info.empty:
            stats.unknown += 1
        else:
            stats.resolved += 1

        rows.append(
            {
                "ip": address,
                "country_code": info.country_code,
                "country_name": info.country_name,
                "city": info.city,
                "latitude": info.latitude,
                "longitude": info.longitude,
                "asn": info.asn,
                "as_org": info.as_org,
                # Set even when nothing was found: "looked up, not known" has
                # to be distinguishable from "not looked up yet".
                "geo_checked_at": datetime.now(UTC),
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
    """Upsert the looked-up addresses."""
    statement = insert(IpIntelRow).values(rows)
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[IpIntelRow.ip],
            set_={column: statement.excluded[column] for column in rows[0] if column != "ip"},
        )
    )
    logger.info("Wrote %d enriched addresses", len(rows))


def enrich_pending(
    db: DbSession,
    locator: Locator,
    limit: int | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> EnrichStats:
    """Resolve every address not looked up yet."""
    addresses = pending_addresses(db, limit)
    logger.info("%d addresses to resolve", len(addresses))
    return enrich_addresses(db, locator, addresses, batch_size)
