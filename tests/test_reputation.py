"""Tests for reputation lookups.

Nothing here touches the network or needs an API key. The client is exercised
against a transport that returns canned responses, and the worker against a
fake source — which is possible because the worker depends on the narrow
`Reputer` protocol rather than on AbuseIPDB.

Every address in this file is from the documentation range reserved by
RFC 5737, so no real address appears in the repository.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest

from honeypot_ai.reputation import worker as worker_module
from honeypot_ai.reputation.abuseipdb import (
    AbuseIpdbClient,
    AuthenticationError,
    QuotaExhausted,
    ReputationInfo,
    parse_response,
)
from honeypot_ai.reputation.worker import ReputationStats, check_addresses

REPORTED = {
    "data": {
        "ipAddress": "203.0.113.42",
        "isPublic": True,
        "abuseConfidenceScore": 100,
        "countryCode": "CN",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting",
        "domain": "example.net",
        "isTor": False,
        "totalReports": 1337,
        "numDistinctUsers": 212,
        "lastReportedAt": "2026-10-04T08:15:00+00:00",
    }
}

CLEAN = {
    "data": {
        "ipAddress": "203.0.113.51",
        "isPublic": True,
        "abuseConfidenceScore": 0,
        "usageType": "Fixed Line ISP",
        "isp": "Example Telecom",
        "isTor": False,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
    }
}


def client_returning(*responses: httpx.Response) -> AbuseIpdbClient:
    """A client whose transport replays the given responses in order."""
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        return queue.pop(0) if queue else httpx.Response(200, json=CLEAN)

    transport = httpx.MockTransport(handler)
    return AbuseIpdbClient(
        api_key="test-key",
        min_interval=0.0,
        client=httpx.Client(transport=transport),
    )


class FakeReputer:
    """A reputation source with two known addresses and nothing else."""

    KNOWN = {
        "203.0.113.42": ReputationInfo(
            abuse_score=100,
            total_reports=1337,
            distinct_reporters=212,
            last_reported_at=datetime(2026, 10, 4, 8, 15, tzinfo=UTC),
            isp="Example Hosting",
            usage_type="Data Center/Web Hosting/Transit",
            is_tor=False,
        ),
        "203.0.113.51": ReputationInfo(abuse_score=0, total_reports=0, isp="Example Telecom"),
    }

    def __init__(self, fail_after: int | None = None) -> None:
        self.calls: list[str] = []
        self._fail_after = fail_after

    def lookup(self, ip: str) -> ReputationInfo:
        if self._fail_after is not None and len(self.calls) >= self._fail_after:
            raise QuotaExhausted("no quota left")
        self.calls.append(ip)
        return self.KNOWN.get(ip, ReputationInfo())


def test_a_reported_address_is_parsed_in_full() -> None:
    info = parse_response(REPORTED)
    assert info.abuse_score == 100
    assert info.total_reports == 1337
    assert info.distinct_reporters == 212
    assert info.usage_type == "Data Center/Web Hosting/Transit"
    assert info.last_reported_at == datetime(2026, 10, 4, 8, 15, tzinfo=UTC)
    assert not info.empty


def test_a_clean_address_is_a_result_not_a_miss() -> None:
    """A score of zero is an answer: this address has never been reported."""
    info = parse_response(CLEAN)
    assert info.abuse_score == 0
    assert info.last_reported_at is None
    assert not info.empty


def test_a_malformed_payload_yields_nothing_rather_than_raising() -> None:
    assert parse_response({}).empty
    assert parse_response({"data": "not a dict"}).empty
    assert parse_response({"data": {"abuseConfidenceScore": "high"}}).empty


def test_an_unparseable_timestamp_is_dropped_not_fatal() -> None:
    payload = {"data": {"abuseConfidenceScore": 3, "lastReportedAt": "last Tuesday"}}
    info = parse_response(payload)
    assert info.abuse_score == 3
    assert info.last_reported_at is None


def test_an_empty_key_is_refused_before_any_request() -> None:
    with pytest.raises(AuthenticationError):
        AbuseIpdbClient(api_key="")


def test_a_rejected_key_raises_rather_than_retrying() -> None:
    with client_returning(httpx.Response(401, json={"errors": []})) as client:
        with pytest.raises(AuthenticationError):
            client.lookup("203.0.113.42")


def test_a_server_error_is_retried_and_then_succeeds() -> None:
    with client_returning(
        httpx.Response(500, text="nope"),
        httpx.Response(200, json=REPORTED),
    ) as client:
        info = client.lookup("203.0.113.42")
    assert info.abuse_score == 100


def test_an_unusable_address_is_skipped_without_retrying() -> None:
    """A 422 means the address itself is the problem; retrying fails identically."""
    with client_returning(httpx.Response(422, json={"errors": []})) as client:
        assert client.lookup("198.51.100.0").empty


def test_the_remaining_quota_is_read_from_the_response() -> None:
    response = httpx.Response(200, json=CLEAN, headers={"X-RateLimit-Remaining": "873"})
    with client_returning(response) as client:
        client.lookup("203.0.113.51")
        assert client.remaining == 873


def test_a_persistent_rate_limit_becomes_quota_exhausted() -> None:
    limited = [httpx.Response(429, headers={"Retry-After": "0"}) for _ in range(4)]
    with client_returning(*limited) as client:
        with pytest.raises(QuotaExhausted):
            client.lookup("203.0.113.42")


def test_stats_separate_reported_from_clean_from_unknown() -> None:
    stats = ReputationStats(pending=3, checked=3, reported=1, unknown=1)
    assert "3 checked" in str(stats)
    assert "1 with reports" in str(stats)


@pytest.mark.parametrize("address", ["203.0.113.42", "203.0.113.51"])
def test_the_fake_source_answers_known_addresses(address: str) -> None:
    assert not FakeReputer().lookup(address).empty


def test_an_unknown_address_is_an_empty_result() -> None:
    assert FakeReputer().lookup("198.51.100.7").empty


class FakeDb:
    """Just enough of a SQLAlchemy session for the worker to run against."""

    def execute(self, statement: object) -> None:
        pass

    def commit(self) -> None:
        pass


def test_a_quota_stop_ends_the_run_without_losing_earlier_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The worker stops cleanly rather than raising, and keeps what it paid for."""
    written: list[dict[str, object]] = []
    monkeypatch.setattr(
        worker_module,
        "_write",
        lambda _db, rows: written.extend(rows),
    )

    reputer = FakeReputer(fail_after=1)
    stats = check_addresses(
        FakeDb(),  # type: ignore[arg-type]
        reputer,
        ["203.0.113.42", "203.0.113.51"],
    )

    assert stats.stopped_early
    assert stats.checked == 1
    assert [row["ip"] for row in written] == ["203.0.113.42"]


def test_a_full_run_records_every_address(monkeypatch: pytest.MonkeyPatch) -> None:
    written: list[dict[str, object]] = []
    monkeypatch.setattr(
        worker_module,
        "_write",
        lambda _db, rows: written.extend(rows),
    )

    stats = check_addresses(
        FakeDb(),  # type: ignore[arg-type]
        FakeReputer(),
        ["203.0.113.42", "203.0.113.51", "198.51.100.7"],
    )

    assert not stats.stopped_early
    assert (stats.checked, stats.reported, stats.unknown) == (3, 1, 1)
    assert len(written) == 3
    # Stamped even for the address nothing was known about, so it is not
    # re-checked on every run for the rest of the window.
    assert all(row["abuse_checked_at"] is not None for row in written)
