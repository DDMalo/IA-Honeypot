"""Reputation lookups against AbuseIPDB.

Geolocation says where a machine is; reputation says whether anyone else has
seen it misbehave. The two answer different questions and come from different
places, which is why this is a separate stage rather than another field on the
GeoIP lookup: it crosses the network, it is rate-limited, and it goes stale.

Three things shape the design.

**The budget is small.** The free tier allows 1,000 checks a day. The honeypot
sees far more sessions than that, but far fewer distinct addresses, and an
address only needs checking once in a while — so the work is per address, the
result is cached in the database, and a run stops cleanly when the quota says
to rather than burning through tomorrow's allowance.

**Reputation is not a fact about the attacker.** A high score means other
people have reported the address. That is a crowd-sourced signal with all the
bias that implies: hosting ranges are reported heavily, residential ones
barely. It is evidence, not a verdict.

**`usage_type` is the field worth having.** It separates a datacentre address
— someone renting a machine to scan the internet — from a residential one,
which is usually a compromised router or camera whose owner has no idea. That
distinction is what the classifier in v0.4.0 will want.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import Any, Protocol, Self

import httpx

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"

#: How far back AbuseIPDB should count reports. Ninety days is its own default
#: and keeps the score responsive without discarding a slow, patient scanner.
DEFAULT_MAX_AGE_IN_DAYS = 90

#: Seconds to wait between requests. The free tier has no documented per-second
#: limit, but hammering an API that is given away for free is bad manners.
DEFAULT_MIN_INTERVAL = 0.25

DEFAULT_TIMEOUT = 15.0
MAX_ATTEMPTS = 4


class ReputationError(RuntimeError):
    """A lookup failed in a way the caller has to know about."""


class AuthenticationError(ReputationError):
    """The API key was rejected. Retrying will not help."""


class QuotaExhausted(ReputationError):
    """The daily allowance is spent. The run should stop and resume tomorrow."""


@dataclass(frozen=True)
class ReputationInfo:
    """What AbuseIPDB says about one address. Every field may be absent."""

    abuse_score: int | None = None
    total_reports: int | None = None
    distinct_reporters: int | None = None
    last_reported_at: datetime | None = None
    isp: str | None = None
    usage_type: str | None = None
    domain: str | None = None
    is_tor: bool | None = None

    @property
    def empty(self) -> bool:
        """True when the service returned nothing usable about the address."""
        return self.abuse_score is None


class Reputer(Protocol):
    """What the worker needs from a reputation source.

    The worker depends on this rather than on the client below, so it can be
    tested without an API key and without touching the network.
    """

    def lookup(self, ip: str) -> ReputationInfo: ...


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _as_datetime(value: Any) -> datetime | None:
    """AbuseIPDB returns ISO 8601 with an offset; anything else is dropped."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        logger.debug("Unparseable timestamp from AbuseIPDB: %r", value)
        return None


def parse_response(payload: dict[str, Any]) -> ReputationInfo:
    """Turn one `/check` response into a `ReputationInfo`.

    Pulled out of the client so it can be tested against recorded payloads,
    and so a field the API adds or renames breaks in one obvious place.
    """
    data = payload.get("data")
    if not isinstance(data, dict):
        return ReputationInfo()

    return ReputationInfo(
        abuse_score=_as_int(data.get("abuseConfidenceScore")),
        total_reports=_as_int(data.get("totalReports")),
        distinct_reporters=_as_int(data.get("numDistinctUsers")),
        last_reported_at=_as_datetime(data.get("lastReportedAt")),
        isp=_as_str(data.get("isp")),
        usage_type=_as_str(data.get("usageType")),
        domain=_as_str(data.get("domain")),
        is_tor=_as_bool(data.get("isTor")),
    )


class AbuseIpdbClient:
    """A rate-limited, retrying client for the one endpoint this project uses.

    `remaining` tracks the `X-RateLimit-Remaining` header the API returns on
    every response, so the worker can stop before the quota runs out instead of
    discovering it through a wall of 429s.
    """

    def __init__(
        self,
        api_key: str,
        max_age_in_days: int = DEFAULT_MAX_AGE_IN_DAYS,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        if not api_key:
            raise AuthenticationError("No AbuseIPDB API key. Set ABUSEIPDB_API_KEY in .env.")

        self._max_age_in_days = max_age_in_days
        self._min_interval = min_interval
        self._last_request = 0.0
        self.remaining: int | None = None

        self._client = client or httpx.Client(
            timeout=timeout,
            headers={"Key": api_key, "Accept": "application/json"},
        )

    def lookup(self, ip: str) -> ReputationInfo:
        """Check one address, waiting and retrying as the API asks.

        Raises `QuotaExhausted` when the allowance is spent and
        `AuthenticationError` when the key is wrong. Everything else — a
        timeout, a 500, a reply that is not JSON — is logged and returns an
        empty result, because one unlucky address must not end the run.
        """
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._wait_turn()

            try:
                response = self._client.get(
                    API_URL,
                    params={"ipAddress": ip, "maxAgeInDays": self._max_age_in_days},
                )
            except httpx.HTTPError as exc:
                logger.warning("Request for %s failed (attempt %d): %s", ip, attempt, exc)
                self._back_off(attempt)
                continue

            self._note_remaining(response)

            if response.status_code == httpx.codes.UNAUTHORIZED:
                raise AuthenticationError("AbuseIPDB rejected the API key.")

            if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
                if attempt == MAX_ATTEMPTS:
                    raise QuotaExhausted("AbuseIPDB rate limit reached; stopping for now.")
                self._back_off(attempt, response.headers.get("Retry-After"))
                continue

            if response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR:
                logger.warning("AbuseIPDB returned %d for %s", response.status_code, ip)
                self._back_off(attempt)
                continue

            if response.status_code != httpx.codes.OK:
                # A 422 means the address itself is the problem — a private
                # range, say. Retrying would fail identically.
                logger.warning("AbuseIPDB returned %d for %s; skipping", response.status_code, ip)
                return ReputationInfo()

            try:
                payload = response.json()
            except ValueError:
                logger.warning("AbuseIPDB returned something that is not JSON for %s", ip)
                return ReputationInfo()

            return parse_response(payload)

        logger.warning("Giving up on %s after %d attempts", ip, MAX_ATTEMPTS)
        return ReputationInfo()

    def _wait_turn(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _back_off(self, attempt: int, retry_after: str | None = None) -> None:
        """Wait before retrying: what the server asked for, or 2, 4, 8 seconds."""
        if retry_after is not None:
            try:
                time.sleep(min(float(retry_after), 60.0))
                return
            except ValueError:
                pass
        time.sleep(2.0**attempt)

    def _note_remaining(self, response: httpx.Response) -> None:
        header = response.headers.get("X-RateLimit-Remaining")
        if header is None:
            return
        try:
            self.remaining = int(header)
        except ValueError:
            return
        if self.remaining <= 0:
            logger.info("AbuseIPDB quota is spent for today")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
