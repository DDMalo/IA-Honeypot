"""A weekly report of what the honeypot saw, short enough to be read.

Eight sections, each answering one question a person would ask on a Monday:
how much arrived, what it was trying to do, which ATT&CK techniques it used,
which campaigns dominated, where it came from, which credentials it tried,
which files it left, and whether the two classifiers agree.

**Aggregates only.** The privacy notes allow counts, countries, networks and
credential frequencies, never a list of addresses, and that is the line here.
Campaigns are described by what they did — intent, techniques, size — and not
by their commands: a command log can carry a payload (the 13 October dropper
was an ELF typed in hex) and is treated like a sample.

**Attacker text is quoted, never rendered.** Usernames and passwords tried are
chosen by the attacker, and a report is Markdown: a password of
`[click](http://…)` would otherwise become a link. Every such string is cut
short, stripped of anything that could close a code span, and shown inside
one.

Techniques come from the rule engine's behaviours through the hand-written
mapping, never from a model, so the same week always produces the same
techniques.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import TextClause, text
from sqlalchemy.orm import Session as DbSession

from honeypot_ai.attack.catalogue import Catalogue, load
from honeypot_ai.attack.mapping import techniques_for
from honeypot_ai.classify.taxonomy import INTENT_PRECEDENCE, Behaviour, Intent

TOP = 5
LLM_PREFIX = "gemini:"


@dataclass(frozen=True)
class Week:
    """An ISO week, Monday 00:00 to the next Monday, in UTC."""

    start: datetime

    @classmethod
    def of(cls, day: date) -> Week:
        monday = day - timedelta(days=day.weekday())
        return cls(datetime(monday.year, monday.month, monday.day, tzinfo=UTC))

    @classmethod
    def parse(cls, label: str) -> Week:
        """`2026-W45` → that week."""
        return cls.of(datetime.strptime(label + "-1", "%G-W%V-%u").date())

    @classmethod
    def last_complete(cls, now: datetime) -> Week:
        return cls.of(now.date()).previous

    @property
    def end(self) -> datetime:
        return self.start + timedelta(days=7)

    @property
    def previous(self) -> Week:
        return Week(self.start - timedelta(days=7))

    @property
    def label(self) -> str:
        year, week, _ = self.start.isocalendar()
        return f"{year}-W{week:02d}"


@dataclass(frozen=True)
class Campaign:
    sessions: int
    sources: int
    intent: str
    behaviours: tuple[str, ...]
    first_seen: datetime
    authenticated: bool
    commands: int


@dataclass(frozen=True)
class CapturedFile:
    sha256: str
    sessions: int
    malicious: int | None
    threat_label: str | None
    file_type: str | None


@dataclass
class WeeklyData:
    week: Week
    sessions: int = 0
    sessions_before: int = 0
    sources: int = 0
    countries: int = 0
    with_commands: int = 0
    new_sequences: int = 0
    intents: Counter[str] = field(default_factory=Counter)
    intents_before: Counter[str] = field(default_factory=Counter)
    behaviour_sets: Counter[tuple[str, ...]] = field(default_factory=Counter)
    behaviour_sets_before: Counter[tuple[str, ...]] = field(default_factory=Counter)
    campaigns: list[Campaign] = field(default_factory=list)
    top_countries: list[tuple[str, int]] = field(default_factory=list)
    top_networks: list[tuple[str, int]] = field(default_factory=list)
    top_credentials: list[tuple[str, str, int]] = field(default_factory=list)
    files: list[CapturedFile] = field(default_factory=list)
    both_labelled: int = 0
    agreed: int = 0
    disagreements: list[tuple[str, str, int]] = field(default_factory=list)


# --- Gathering ---------------------------------------------------------------

_COUNT_SESSIONS = text("SELECT count(*) FROM sessions WHERE started_at >= :a AND started_at < :b")
_COUNT_SOURCES = text(
    "SELECT count(DISTINCT src_ip) FROM sessions WHERE started_at >= :a AND started_at < :b"
)
_COUNT_COUNTRIES = text(
    "SELECT count(DISTINCT i.country_code) FROM sessions s JOIN ip_intel i ON i.ip = s.src_ip "
    "WHERE s.started_at >= :a AND s.started_at < :b"
)
_COUNT_WITH_COMMANDS = text(
    "SELECT count(*) FROM sessions WHERE started_at >= :a AND started_at < :b AND command_count > 0"
)
_INTENTS = text(
    "SELECT l.intent, count(*) FROM session_labels l JOIN sessions s USING (session_id) "
    "WHERE l.classifier = 'rules' AND s.started_at >= :a AND s.started_at < :b "
    "GROUP BY l.intent"
)
_BEHAVIOUR_SETS = text(
    "SELECT l.behaviours, count(*) "
    "FROM session_labels l JOIN sessions s USING (session_id) "
    "WHERE l.classifier = 'rules' AND s.started_at >= :a AND s.started_at < :b "
    "GROUP BY l.behaviours"
)
#: Sequences ranked by sessions this week, with when each was first seen at
#: all. The fingerprint is the one the evaluation sample and the by-sequence
#: classifier use, so "a sequence" means the same thing everywhere.
_CAMPAIGNS = text(
    """
    WITH everything AS (
        SELECT s.session_id, s.started_at, s.src_ip, s.authenticated,
               count(c.id) AS commands,
               md5(coalesce(string_agg(c.input, E'\\n' ORDER BY c.seq), '')
                   || '|' || s.authenticated::text) AS fingerprint
        FROM sessions s
        LEFT JOIN commands c ON c.session_id = s.session_id
        GROUP BY s.session_id
    ),
    first AS (SELECT fingerprint, min(started_at) AS first_seen
              FROM everything GROUP BY fingerprint),
    this_week AS (SELECT * FROM everything WHERE started_at >= :a AND started_at < :b)
    SELECT w.fingerprint, count(*) AS sessions, count(DISTINCT w.src_ip) AS sources,
           min(w.session_id) AS representative, bool_or(w.authenticated) AS authenticated,
           max(w.commands) AS commands, f.first_seen
    FROM this_week w JOIN first f USING (fingerprint)
    GROUP BY w.fingerprint, f.first_seen
    ORDER BY sessions DESC, w.fingerprint
    """
)
_RULE_LABEL = text(
    "SELECT intent, behaviours FROM session_labels WHERE session_id = :s AND classifier = 'rules'"
)
_TOP_COUNTRIES = text(
    "SELECT coalesce(i.country_name, 'unknown') AS name, count(*) AS n "
    "FROM sessions s LEFT JOIN ip_intel i ON i.ip = s.src_ip "
    "WHERE s.started_at >= :a AND s.started_at < :b "
    "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT :top"
)
_TOP_NETWORKS = text(
    "SELECT coalesce(i.as_org, 'unknown') AS name, count(*) AS n "
    "FROM sessions s LEFT JOIN ip_intel i ON i.ip = s.src_ip "
    "WHERE s.started_at >= :a AND s.started_at < :b "
    "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT :top"
)


def _scalar(db: DbSession, statement: TextClause, a: datetime, b: datetime) -> int:
    return int(db.execute(statement, {"a": a, "b": b}).scalar_one() or 0)


def _intents(db: DbSession, week: Week) -> Counter[str]:
    rows = db.execute(_INTENTS, {"a": week.start, "b": week.end})
    return Counter({intent: n for intent, n in rows})


def _behaviour_sets(db: DbSession, week: Week) -> Counter[tuple[str, ...]]:
    rows = db.execute(_BEHAVIOUR_SETS, {"a": week.start, "b": week.end})
    return Counter({tuple(sorted(behaviours or [])): n for behaviours, n in rows})


def gather(db: DbSession, week: Week) -> WeeklyData:
    a, b = week.start, week.end
    data = WeeklyData(week=week)

    data.sessions = _scalar(db, _COUNT_SESSIONS, a, b)
    data.sessions_before = _scalar(db, _COUNT_SESSIONS, week.previous.start, a)
    data.sources = _scalar(db, _COUNT_SOURCES, a, b)
    data.countries = _scalar(db, _COUNT_COUNTRIES, a, b)
    data.with_commands = _scalar(db, _COUNT_WITH_COMMANDS, a, b)

    data.intents, data.intents_before = _intents(db, week), _intents(db, week.previous)
    data.behaviour_sets = _behaviour_sets(db, week)
    data.behaviour_sets_before = _behaviour_sets(db, week.previous)

    rows = db.execute(_CAMPAIGNS, {"a": a, "b": b}).all()
    data.new_sequences = sum(1 for row in rows if row.first_seen >= a)
    for row in rows[:TOP]:
        label = db.execute(_RULE_LABEL, {"s": row.representative}).first()
        data.campaigns.append(
            Campaign(
                sessions=row.sessions,
                sources=row.sources,
                intent=label.intent if label else "unlabelled",
                behaviours=tuple(sorted(label.behaviours or [])) if label else (),
                first_seen=row.first_seen,
                authenticated=row.authenticated,
                commands=row.commands,
            )
        )

    for statement, target in (
        (_TOP_COUNTRIES, data.top_countries),
        (_TOP_NETWORKS, data.top_networks),
    ):
        ranked = db.execute(statement, {"a": a, "b": b, "top": TOP}).all()
        target.extend((name, n) for name, n in ranked)

    rows = db.execute(
        text(
            "SELECT username, password, count(*) FROM login_attempts "
            "WHERE occurred_at >= :a AND occurred_at < :b "
            "GROUP BY 1, 2 ORDER BY 3 DESC, 1, 2 LIMIT :top"
        ),
        {"a": a, "b": b, "top": TOP},
    ).all()
    data.top_credentials = [(u, p, n) for u, p, n in rows]

    rows = db.execute(
        text(
            """
            SELECT t.shasum, count(DISTINCT t.session_id) AS sessions,
                   f.malicious, f.threat_label, f.file_type
            FROM file_transfers t LEFT JOIN file_intel f ON f.sha256 = t.shasum
            WHERE t.shasum IS NOT NULL AND t.occurred_at >= :a AND t.occurred_at < :b
              AND NOT EXISTS (SELECT 1 FROM file_transfers e
                              WHERE e.shasum = t.shasum AND e.occurred_at < :a)
            GROUP BY t.shasum, f.malicious, f.threat_label, f.file_type
            ORDER BY sessions DESC, t.shasum
            """
        ),
        {"a": a, "b": b},
    ).all()
    data.files = [CapturedFile(*row) for row in rows]

    rows = db.execute(
        text(
            """
            SELECT r.intent, g.intent, count(*)
            FROM session_labels r
            JOIN session_labels g ON g.session_id = r.session_id AND g.classifier LIKE :llm
            JOIN sessions s ON s.session_id = r.session_id
            WHERE r.classifier = 'rules' AND s.started_at >= :a AND s.started_at < :b
            GROUP BY 1, 2
            """
        ),
        {"a": a, "b": b, "llm": LLM_PREFIX + "%"},
    ).all()
    data.both_labelled = sum(n for _, _, n in rows)
    data.agreed = sum(n for rule, model, n in rows if rule == model)
    data.disagreements = sorted(
        ((rule, model, n) for rule, model, n in rows if rule != model),
        key=lambda row: (-row[2], row[0], row[1]),
    )[:TOP]
    return data


# --- Rendering ---------------------------------------------------------------


def quote(value: str, limit: int = 32) -> str:
    """Attacker-chosen text, safe to put in a Markdown table."""
    cleaned = "".join(c if c.isprintable() else "?" for c in value).replace("`", "'")
    cleaned = cleaned.replace("|", "¦")
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1] + "…"
    return f"`{cleaned}`" if cleaned else "*(empty)*"


def cell(value: str) -> str:
    """Third-party text (country and network names) made safe for a table cell."""
    return "".join(c if c.isprintable() else " " for c in value).replace("|", "¦")


def _count(n: int) -> str:
    return f"{n:,}" if n else ""


def _change(now: int, before: int) -> str:
    if before == 0:
        return "new" if now else "—"
    return f"{(now - before) / before:+.0%}"


def technique_counts(
    behaviour_sets: Counter[tuple[str, ...]], catalogue: Catalogue
) -> Counter[str]:
    """Sessions per technique. A session counts once per technique it evidences."""
    counts: Counter[str] = Counter()
    for behaviours, sessions in behaviour_sets.items():
        known = [Behaviour(b) for b in behaviours if b in Behaviour._value2member_map_]
        for technique in techniques_for(known, catalogue):
            counts[technique.id] += sessions
    return counts


def _ordered_intents(intents: Iterable[str]) -> list[str]:
    order = [i.value for i in INTENT_PRECEDENCE] + [Intent.OTHER.value]
    return sorted(intents, key=lambda i: order.index(i) if i in order else len(order))


def render(data: WeeklyData, catalogue: Catalogue | None = None) -> str:
    catalogue = catalogue or load()
    w = data.week
    out = [
        f"# Honeypot weekly report, {w.label}",
        "",
        f"{w.start:%A %d %B %Y} to {w.end - timedelta(days=1):%A %d %B %Y}, UTC. "
        "Aggregates only: no addresses, no commands.",
        "",
        "## The week in numbers",
        "",
        "| | This week | Change |",
        "|---|---:|---:|",
        f"| Sessions | {data.sessions:,} | {_change(data.sessions, data.sessions_before)} |",
        f"| Source addresses | {data.sources:,} | |",
        f"| Countries | {data.countries:,} | |",
        f"| Sessions that ran commands | {data.with_commands:,} | |",
        f"| Command sequences never seen before | {data.new_sequences:,} | |",
        "",
        "## What they were trying to do",
        "",
        "Intent from the rule engine, furthest step reached.",
        "",
        "| Intent | Sessions | Share | Change |",
        "|---|---:|---:|---:|",
    ]
    total = sum(data.intents.values()) or 1
    for intent in _ordered_intents(data.intents.keys() | data.intents_before.keys()):
        n = data.intents.get(intent, 0)
        change = _change(n, data.intents_before.get(intent, 0))
        out.append(f"| {intent} | {n:,} | {n / total:.1%} | {change} |")

    now, before = (
        technique_counts(data.behaviour_sets, catalogue),
        technique_counts(data.behaviour_sets_before, catalogue),
    )
    out += [
        "",
        f"## ATT&CK techniques (Enterprise {catalogue.version})",
        "",
        "Derived from observed behaviours. **New** means not seen the week before.",
        "",
    ]
    if not now:
        out += ["No technique was evidenced this week.", ""]
    for tactic in catalogue.tactics:
        rows = sorted(
            (
                (n, tid)
                for tid, n in now.items()
                if tactic.shortname in catalogue.techniques[tid].tactics
            ),
            key=lambda r: (-r[0], r[1]),
        )
        if not rows:
            continue
        out += [f"**{tactic.name}**", "", "| Technique | Sessions | |", "|---|---:|---|"]
        for n, tid in rows:
            technique = catalogue.techniques[tid]
            flag = "**new**" if tid not in before else ""
            out.append(f"| [{tid}]({technique.url}) {technique.name} | {n:,} | {flag} |")
        out.append("")

    out += ["## The largest campaigns", ""]
    if not data.campaigns:
        out.append("No sessions this week.")
    else:
        out += [
            "One campaign is one exact command sequence. Described by what it did, not by its "
            "commands.",
            "",
            "| Sessions | Sources | Intent | Techniques | First seen |",
            "|---:|---:|---|---|---|",
        ]
        for c in data.campaigns:
            known = [Behaviour(b) for b in c.behaviours if b in Behaviour._value2member_map_]
            techniques = ", ".join(t.id for t in techniques_for(known, catalogue)) or "—"
            what = c.intent if c.commands else f"{c.intent} (no commands)"
            seen = f"{c.first_seen:%Y-%m-%d}" + (" **new**" if c.first_seen >= w.start else "")
            out.append(f"| {c.sessions:,} | {c.sources:,} | {what} | {techniques} | {seen} |")
    out.append("")

    out += [
        "## Where it came from",
        "",
        "| Country | Sessions | | Network | Sessions |",
        "|---|---:|---|---|---:|",
    ]
    for i in range(max(len(data.top_countries), len(data.top_networks))):
        country = data.top_countries[i] if i < len(data.top_countries) else ("", 0)
        network = data.top_networks[i] if i < len(data.top_networks) else ("", 0)
        out.append(
            f"| {cell(country[0])} | {_count(country[1])} | "
            f"| {cell(network[0])} | {_count(network[1])} |"
        )

    out += ["", "## Credentials tried most", ""]
    if not data.top_credentials:
        out.append("No login attempts this week.")
    else:
        out += ["| Username | Password | Attempts |", "|---|---|---:|"]
        out += [f"| {quote(u)} | {quote(p)} | {n:,} |" for u, p, n in data.top_credentials]

    out += ["", "## Files captured for the first time", ""]
    if not data.files:
        out.append("None this week.")
    else:
        out += ["| SHA-256 | Sessions | VirusTotal | Type |", "|---|---:|---|---|"]
        for f in data.files[:10]:
            verdict = (
                "not looked up"
                if f.malicious is None
                else f"{f.malicious} engines"
                + (f", {quote(f.threat_label)}" if f.threat_label else "")
            )
            out.append(f"| `{f.sha256}` | {f.sessions} | {verdict} | {f.file_type or '—'} |")
        if len(data.files) > 10:
            out.append(f"\nand {len(data.files) - 10} more.")

    out += ["", "## Rules and model", ""]
    if not data.both_labelled:
        out.append("No session this week has been labelled by both yet.")
    else:
        out.append(
            f"Of {data.both_labelled:,} sessions labelled by both the rules and the language "
            f"model, they agree on {data.agreed:,} ({data.agreed / data.both_labelled:.1%}). "
            "Where they disagree is where to look first: on the hand-labelled set the model "
            "was right more often."
        )
        if data.disagreements:
            out += ["", "| Rules say | Model says | Sessions |", "|---|---|---:|"]
            out += [f"| {r} | {m} | {n:,} |" for r, m, n in data.disagreements]

    out += ["", "---", "", catalogue.attribution, ""]
    return "\n".join(out)


def summary(data: WeeklyData, catalogue: Catalogue | None = None) -> str:
    """Three lines for a phone notification. Aggregates only, like the report."""
    catalogue = catalogue or load()
    lines = [
        f"{data.sessions:,} sessions ({_change(data.sessions, data.sessions_before)}), "
        f"{data.new_sequences:,} new command sequences."
    ]
    counts = technique_counts(data.behaviour_sets, catalogue)
    before = technique_counts(data.behaviour_sets_before, catalogue)
    fresh = sorted((t for t in counts if t not in before), key=lambda t: (-counts[t], t))
    if fresh:
        names = ", ".join(f"{t} {catalogue.techniques[t].name}" for t in fresh[:3])
        lines.append(f"New techniques: {names}.")
    if data.files:
        lines.append(f"{len(data.files)} file(s) captured for the first time.")
    return "\n".join(lines)
