"""Geolocation and network lookups against MaxMind's GeoLite2 databases.

The databases are files on disk, queried offline. That is a deliberate choice
over a web API: tens of thousands of addresses can be resolved in seconds, with
no rate limit, no key in every request, and nothing about the honeypot's
traffic sent to a third party.

Two honest caveats, both recorded here because the analysis depends on them:

* **Geolocation is an estimate.** It places the machine emitting the packets.
  For a botnet that is a compromised device in someone's home, not an attacker.
  Country and network are worth reasoning about; the city rarely is.
* **The data ages.** Address blocks are reassigned, so a lookup is only as good
  as the database file, which is why they are refreshed on a timer — and why
  the age of that file is measured here rather than assumed.

The second point was not theoretical. The updater failed on every run for a
fortnight and nothing said so: enrichment carried on labelling every session
with a country and a network, from a file that was quietly getting older. It
never errored. It just became less true. A pipeline that only reports hard
failures cannot see that, so the age of the data is checked where the data is
read.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Protocol, Self

import geoip2.database
import geoip2.errors

logger = logging.getLogger(__name__)

CITY_DB = "GeoLite2-City.mmdb"
ASN_DB = "GeoLite2-ASN.mmdb"

#: MaxMind publishes GeoLite2 twice a week, so a healthy file is three or four
#: days old. Seven means at least two publications were missed, which is an
#: updater that has stopped working rather than a quiet week.
MAX_DATABASE_AGE = timedelta(days=7)


@dataclass(frozen=True)
class DatabaseAge:
    """How old the *data* is, which is not how old the file is.

    Taken from the `build_epoch` in the database's own metadata: the moment
    MaxMind built it. The file's modification time would answer a different
    and much less useful question, because it changes whenever the file is
    copied, restored or touched — including by a sync that moves a stale file
    around and makes it look fresh.
    """

    name: str
    built: datetime
    checked: datetime

    @property
    def age(self) -> timedelta:
        return self.checked - self.built

    @property
    def stale(self) -> bool:
        return self.age > MAX_DATABASE_AGE

    def __str__(self) -> str:
        return f"{self.name}: built {self.built:%Y-%m-%d}, {self.age.days} day(s) old"


@dataclass(frozen=True)
class GeoInfo:
    """What the databases say about one address. Every field may be absent."""

    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    as_org: str | None = None

    @property
    def empty(self) -> bool:
        """True when neither database knew anything about the address."""
        return self.country_code is None and self.asn is None


class Locator(Protocol):
    """What the enrichment worker needs from a lookup source.

    Declaring the dependency this narrowly is what lets the worker be tested
    without shipping a 60 MB database into the repository.
    """

    def lookup(self, ip: str) -> GeoInfo: ...


class GeoLite2Locator:
    """Reads the GeoLite2 City and ASN databases.

    Both are optional: a missing file degrades the result rather than failing,
    because partial enrichment is more useful than none.
    """

    def __init__(self, directory: Path | str) -> None:
        self._directory = Path(directory)
        self._city: geoip2.database.Reader | None = None
        self._asn: geoip2.database.Reader | None = None

        city_path = self._directory / CITY_DB
        asn_path = self._directory / ASN_DB

        if city_path.is_file():
            self._city = geoip2.database.Reader(str(city_path))
        else:
            logger.warning("No %s in %s; locations will be empty", CITY_DB, self._directory)

        if asn_path.is_file():
            self._asn = geoip2.database.Reader(str(asn_path))
        else:
            logger.warning("No %s in %s; networks will be empty", ASN_DB, self._directory)

    @property
    def available(self) -> bool:
        """True when at least one database could be opened."""
        return self._city is not None or self._asn is not None

    def ages(self, now: datetime | None = None) -> tuple[DatabaseAge, ...]:
        """How old each open database is, newest file first in the pair order."""
        checked = now or datetime.now(UTC)
        found: list[DatabaseAge] = []

        for name, reader in ((CITY_DB, self._city), (ASN_DB, self._asn)):
            if reader is None:
                continue
            built = datetime.fromtimestamp(reader.metadata().build_epoch, tz=UTC)
            found.append(DatabaseAge(name=name, built=built, checked=checked))

        return tuple(found)

    def stale_databases(self, now: datetime | None = None) -> tuple[DatabaseAge, ...]:
        """Those past `MAX_DATABASE_AGE`, for a caller that wants to complain.

        Returned rather than raised. Stale data is worse than fresh data and
        better than none, so this is a warning the operator acts on, not a
        reason to stop enriching.
        """
        return tuple(age for age in self.ages(now) if age.stale)

    def lookup(self, ip: str) -> GeoInfo:
        """Look one address up in both databases.

        An address the databases do not cover — private ranges, unallocated
        space — yields an empty result rather than an error. That is a normal
        outcome, not a failure.
        """
        country_code = country_name = city = None
        latitude = longitude = None
        asn = as_org = None

        if self._city is not None:
            try:
                response = self._city.city(ip)
                country_code = response.country.iso_code
                country_name = response.country.name
                city = response.city.name
                latitude = response.location.latitude
                longitude = response.location.longitude
            except geoip2.errors.AddressNotFoundError:
                pass
            except ValueError:
                logger.debug("Not a usable address for city lookup: %r", ip)

        if self._asn is not None:
            try:
                response_asn = self._asn.asn(ip)
                asn = response_asn.autonomous_system_number
                as_org = response_asn.autonomous_system_organization
            except geoip2.errors.AddressNotFoundError:
                pass
            except ValueError:
                logger.debug("Not a usable address for ASN lookup: %r", ip)

        return GeoInfo(
            country_code=country_code,
            country_name=country_name,
            city=city,
            latitude=latitude,
            longitude=longitude,
            asn=asn,
            as_org=as_org,
        )

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
