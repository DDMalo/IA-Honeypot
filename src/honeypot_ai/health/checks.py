"""Is the pipeline still running? Judged by the age of the data it produces.

Two failures went unnoticed for ten days in this deployment, and neither
produced an error. The rule engine's timer had never been installed, so no
labels were written; later, a query that had stopped being hashable sat in its
first statement for twenty minutes with the timer waiting behind it. A stage
that does not run cannot log that it failed. The only symptom is that its
output stops getting newer.

So every check here asks the database how old the newest thing is, never
whether a process exited cleanly — the same reasoning as reading a GeoIP
database's `build_epoch` instead of its file's modification time. A check
that looks at a service's exit status would have passed throughout both
failures: one service did not exist, and the other had not exited.

Three checks, one per stage that has failed silently or could:

* **sessions** — the newest session started more than six hours ago. A quiet
  day here is 1,600 sessions, about one every minute; six hours of nothing is
  the sensor, the tunnel, the log sync or ingestion, not the internet.
* **rules** — a session ingested more than two hours ago still has no rule
  label. The rules run every thirty minutes and take seconds.
* **llm** — no language-model label has been written in thirty-six hours. The
  model runs once a day, and about a hundred new sequences arrive daily, so a
  healthy day always writes some.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session as DbSession

from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION
from honeypot_ai.db import SessionLabelRow, SessionRow

SESSIONS_MAX_AGE = timedelta(hours=6)
RULES_MAX_LAG = timedelta(hours=2)
LLM_MAX_AGE = timedelta(hours=36)

#: Labels whose classifier name starts with this count as the language model's.
LLM_PREFIX = "gemini:"


@dataclass(frozen=True)
class Check:
    """One stage's verdict. `detail` is shown to a person and sent to a phone,
    so it carries counts and times only — never an address or a command."""

    name: str
    ok: bool
    detail: str

    def __str__(self) -> str:
        return f"{'ok  ' if self.ok else 'FAIL'} {self.name:<9} {self.detail}"


def _age(now: datetime, then: datetime) -> str:
    hours = (now - then).total_seconds() / 3600
    return f"{hours:.1f} h ago ({then:%Y-%m-%d %H:%M} UTC)"


def check_sessions(newest: datetime | None, now: datetime, limit: timedelta) -> Check:
    if newest is None:
        return Check("sessions", False, "no sessions at all")
    return Check("sessions", now - newest <= limit, f"newest session started {_age(now, newest)}")


def check_rules(unlabelled: int, oldest: datetime | None, now: datetime, limit: timedelta) -> Check:
    if unlabelled == 0 or oldest is None:
        return Check("rules", True, "every session ingested over the lag has a rule label")
    return Check(
        "rules",
        False,
        f"{unlabelled} session(s) ingested over {limit.total_seconds() / 3600:.0f} h ago "
        f"have no rule label, the oldest ingested {_age(now, oldest)}",
    )


def check_llm(newest: datetime | None, now: datetime, limit: timedelta) -> Check:
    if newest is None:
        return Check("llm", False, "no language-model label has ever been written")
    return Check("llm", now - newest <= limit, f"newest model label written {_age(now, newest)}")


def run_checks(
    db: DbSession,
    now: datetime,
    *,
    sessions_max_age: timedelta = SESSIONS_MAX_AGE,
    rules_max_lag: timedelta = RULES_MAX_LAG,
    llm_max_age: timedelta = LLM_MAX_AGE,
    llm: bool = True,
) -> list[Check]:
    newest_session = db.execute(select(func.max(SessionRow.started_at))).scalar_one()

    # NOT EXISTS, not NOT IN: the same lesson as the classifier's own query,
    # learned on the same table. A health check that hangs is worse than none.
    has_rule_label = (
        select(SessionLabelRow.session_id)
        .where(
            SessionLabelRow.session_id == SessionRow.session_id,
            SessionLabelRow.classifier == "rules",
            SessionLabelRow.taxonomy_version == TAXONOMY_VERSION,
        )
        .exists()
    )
    unlabelled, oldest = db.execute(
        select(func.count(), func.min(SessionRow.ingested_at)).where(
            SessionRow.ingested_at < now - rules_max_lag, ~has_rule_label
        )
    ).one()

    checks = [
        check_sessions(newest_session, now, sessions_max_age),
        check_rules(unlabelled, oldest, now, rules_max_lag),
    ]
    if llm:
        newest_llm = db.execute(
            select(func.max(SessionLabelRow.labelled_at)).where(
                SessionLabelRow.classifier.startswith(LLM_PREFIX)
            )
        ).scalar_one()
        checks.append(check_llm(newest_llm, now, llm_max_age))
    return checks
