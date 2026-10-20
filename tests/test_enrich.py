"""Tests for address enrichment.

The GeoLite2 databases are 60 MB of licensed data and are not in the
repository, so the worker is tested against a fake locator. That is possible
because the worker depends on the narrow `Locator` protocol rather than on
MaxMind's reader — the design choice and the testability are the same thing.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import geoip2.errors
import pytest

from honeypot_ai.enrich.geoip import (
    CITY_DB,
    MAX_DATABASE_AGE,
    DatabaseAge,
    GeoInfo,
    GeoLite2Locator,
)

TEST_DB = os.getenv("TEST_DATABASE_URL")
needs_db = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")


class FakeLocator:
    """A lookup source with two known addresses and nothing else."""

    KNOWN = {
        "203.0.113.51": GeoInfo(
            country_code="DE",
            country_name="Germany",
            city="Nuremberg",
            latitude=49.45,
            longitude=11.08,
            asn=24940,
            as_org="Hetzner Online GmbH",
        ),
        "203.0.113.42": GeoInfo(country_code="RO", country_name="Romania", asn=9050),
    }

    def __init__(self) -> None:
        self.calls: list[str] = []

    def lookup(self, ip: str) -> GeoInfo:
        self.calls.append(ip)
        return self.KNOWN.get(ip, GeoInfo())


def test_empty_result_is_recognised() -> None:
    assert GeoInfo().empty
    assert not GeoInfo(country_code="ES").empty
    assert not GeoInfo(asn=1234).empty


def test_a_country_without_a_city_is_still_a_result() -> None:
    """City data is frequently missing; that must not count as a failed lookup."""
    assert not FakeLocator.KNOWN["203.0.113.42"].empty


def test_missing_databases_do_not_raise(tmp_path: Path) -> None:
    """Partial enrichment beats none, so a missing file degrades the result."""
    locator = GeoLite2Locator(tmp_path)

    assert not locator.available
    assert locator.lookup("203.0.113.1").empty
    locator.close()


# --- How old the data is ---------------------------------------------------
#
# Written after the updater failed silently on every run for a fortnight while
# enrichment carried on producing confident answers from a frozen file. The
# pipeline never errored; it just stopped being right, and nothing in it was
# looking at that.

NOON = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def built(days_ago: float) -> DatabaseAge:
    return DatabaseAge(name=CITY_DB, built=NOON - timedelta(days=days_ago), checked=NOON)


def test_a_fresh_database_is_not_stale() -> None:
    """MaxMind publishes twice a week, so three days old is a healthy file."""
    assert not built(3).stale


def test_a_database_past_two_missed_publications_is_stale() -> None:
    assert built(8).stale


def test_the_threshold_allows_one_missed_publication_but_not_two() -> None:
    """Tight enough to catch a dead updater, loose enough for a late run."""
    assert MAX_DATABASE_AGE >= timedelta(days=4)
    assert MAX_DATABASE_AGE <= timedelta(days=10)


def test_age_is_measured_from_the_build_not_the_file() -> None:
    """A copied or restored file gets a new mtime and the same stale data, so
    mtime would report a two-week-old database as brand new."""
    stale_data_in_a_fresh_file = DatabaseAge(
        name=CITY_DB,
        built=datetime(2026, 10, 5, 16, 4, tzinfo=UTC),
        checked=NOON,
    )
    assert stale_data_in_a_fresh_file.age.days == 14
    assert stale_data_in_a_fresh_file.stale


def test_the_age_reads_as_a_sentence() -> None:
    """It is printed into a journal somebody will be reading in a hurry."""
    assert str(built(14)) == "GeoLite2-City.mmdb: built 2026-10-06, 14 day(s) old"


def test_no_databases_means_nothing_to_report(tmp_path: Path) -> None:
    """Absent is a different problem from stale, and `available` already says so."""
    locator = GeoLite2Locator(tmp_path)

    assert locator.ages() == ()
    assert locator.stale_databases() == ()
    locator.close()


def test_staleness_is_reported_rather_than_raised(tmp_path: Path) -> None:
    """Old data beats no data: the worker warns and carries on enriching."""
    locator = GeoLite2Locator(tmp_path)
    locator._city = _FrozenReader(datetime(2026, 1, 1, tzinfo=UTC))  # type: ignore[assignment]

    stale = locator.stale_databases(now=NOON)

    assert len(stale) == 1
    assert stale[0].name == CITY_DB
    assert locator.lookup("203.0.113.1").empty  # still answering


class _FrozenReader:
    """Just enough of geoip2's Reader to report a build date."""

    def __init__(self, built: datetime) -> None:
        self._built = built

    def metadata(self) -> object:
        return SimpleNamespace(build_epoch=int(self._built.timestamp()))

    def city(self, ip: str) -> object:
        raise geoip2.errors.AddressNotFoundError(ip)

    def close(self) -> None:
        return None


@pytest.fixture
def db():  # type: ignore[no-untyped-def]
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from honeypot_ai.db import Base

    engine = create_engine(TEST_DB or "", future=True)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    with maker() as session:
        yield session
        session.rollback()
        session.execute(text("TRUNCATE sessions, ip_intel CASCADE"))
        session.commit()


@needs_db
def test_enrichment_stores_what_it_finds(db) -> None:  # type: ignore[no-untyped-def]
    from honeypot_ai.db import IpIntelRow
    from honeypot_ai.enrich.worker import enrich_addresses

    locator = FakeLocator()
    stats = enrich_addresses(db, locator, ["203.0.113.51", "203.0.113.42", "203.0.113.99"])

    assert (stats.pending, stats.resolved, stats.unknown) == (3, 2, 1)

    row = db.get(IpIntelRow, "203.0.113.51")
    assert row is not None
    assert (row.country_code, row.asn, row.as_org) == ("DE", 24940, "Hetzner Online GmbH")


@needs_db
def test_unknown_addresses_are_marked_as_checked(db) -> None:  # type: ignore[no-untyped-def]
    """ "Looked up, not known" must be distinguishable from "not looked up"."""
    from honeypot_ai.db import IpIntelRow
    from honeypot_ai.enrich.worker import enrich_addresses

    enrich_addresses(db, FakeLocator(), ["203.0.113.99"])

    row = db.get(IpIntelRow, "203.0.113.99")
    assert row is not None
    assert row.country_code is None
    assert row.geo_checked_at is not None


@needs_db
def test_only_unresolved_addresses_are_pending(db) -> None:  # type: ignore[no-untyped-def]
    """The lookup budget is finite; nothing is resolved twice."""
    from honeypot_ai.enrich.worker import enrich_addresses, pending_addresses
    from honeypot_ai.ingest.worker import ingest_file

    fixtures = Path(__file__).parent / "fixtures"
    ingest_file(db, fixtures / "cowrie-sample.json")

    first = pending_addresses(db)
    assert len(first) == 3

    locator = FakeLocator()
    enrich_addresses(db, locator, first)

    assert pending_addresses(db) == []
