"""Run a classifier over stored sessions and record what it said.

The selection rule is the interesting part, and it has three cases rather than
the obvious one:

* the session has no label from this classifier — label it;
* it has one, written under an older `TAXONOMY_VERSION` — relabel it, because
  the words it used no longer mean what they meant;
* it has a current one — leave it alone.

Without the middle case a taxonomy change leaves the table a silent mixture of
two vocabularies. Nothing about such a table looks wrong: every row is
well-formed, every label is in the enum, and the counts are nonsense. That is
the same failure mode as a geolocation database that quietly stopped updating,
and it is worth spending a column to avoid.

Sessions are taken newest first. A run cut short by a quota, a timeout or a
closed laptop then leaves the most recent traffic labelled, which is the part
anyone is about to look at.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import selectinload

from honeypot_ai.classify.facts import SessionFacts, facts_from_row
from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Intent, Label
from honeypot_ai.db import SessionLabelRow, SessionRow

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 100

#: A classifier is anything that turns the agreed view of a session into a
#: label. The rule engine is a function; the LLM classifier is an object with
#: a `classify` method. Both satisfy this, which is the point of having the
#: shared `SessionFacts` type at all.
Classifier = Callable[[SessionFacts], Label]


@dataclass
class ClassifyStats:
    """What a run did."""

    pending: int = 0
    labelled: int = 0
    relabelled: int = 0
    unclassified: int = 0
    failed: int = 0

    def __str__(self) -> str:
        parts = [f"{self.pending} sessions pending", f"{self.labelled} labelled"]
        if self.relabelled:
            parts.append(f"{self.relabelled} relabelled for a new taxonomy")
        if self.unclassified:
            parts.append(f"{self.unclassified} unclassified")
        if self.failed:
            parts.append(f"{self.failed} failed")
        return ", ".join(parts)


def pending_sessions(
    db: DbSession,
    classifier: str,
    limit: int | None = None,
    *,
    reclassify: bool = False,
) -> list[SessionRow]:
    """Sessions this classifier has not labelled under the current taxonomy.

    `reclassify` ignores existing labels entirely, for when the prompt or the
    rules changed rather than the vocabulary.
    """
    existing = select(SessionLabelRow.session_id).where(
        SessionLabelRow.classifier == classifier,
        SessionLabelRow.taxonomy_version == TAXONOMY_VERSION,
    )

    statement = select(SessionRow).options(
        selectinload(SessionRow.commands),
        selectinload(SessionRow.login_attempts),
        selectinload(SessionRow.file_transfers),
    )
    if not reclassify:
        statement = statement.where(SessionRow.session_id.not_in(existing))

    statement = statement.order_by(SessionRow.started_at.desc())
    if limit is not None:
        statement = statement.limit(limit)

    return list(db.execute(statement).scalars().all())


def classify_sessions(
    db: DbSession,
    classifier: Classifier,
    name: str,
    rows: Sequence[SessionRow],
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> ClassifyStats:
    """Label the given sessions and write the results in batches.

    One session failing does not stop the run. A classifier that calls a
    language model will hit a timeout eventually, and losing a whole run of
    work to one bad reply would make the worker useless exactly when the
    provider is flaky.
    """
    stats = ClassifyStats(pending=len(rows))
    already = _labelled_under_older_taxonomy(db, name, [row.session_id for row in rows])
    pending_writes: list[dict[str, object]] = []

    for row in rows:
        try:
            label = classifier(facts_from_row(row))
        except Exception:
            logger.exception("Classifier %s failed on session %s", name, row.session_id)
            stats.failed += 1
            continue

        if label.intent is Intent.OTHER and label.confidence == 0.0:
            # The classifier ran and declined to answer. Recorded as such,
            # because "nothing was stored" and "the model gave up" are
            # different facts and only one of them is a bug.
            stats.unclassified += 1

        if row.session_id in already:
            stats.relabelled += 1
        stats.labelled += 1

        pending_writes.append(
            {
                "session_id": row.session_id,
                "classifier": name,
                "intent": str(label.intent),
                "behaviours": sorted(str(behaviour) for behaviour in label.behaviours),
                "operator": str(label.operator),
                "confidence": label.confidence,
                "rationale": label.notes,
                "taxonomy_version": TAXONOMY_VERSION,
            }
        )

        if len(pending_writes) >= batch_size:
            _write(db, pending_writes)
            db.commit()
            pending_writes = []

    if pending_writes:
        _write(db, pending_writes)
    db.commit()

    return stats


def _labelled_under_older_taxonomy(
    db: DbSession, classifier: str, session_ids: Sequence[str]
) -> set[str]:
    """Which of these already have a label, so a rewrite can be counted as one."""
    if not session_ids:
        return set()

    statement = select(SessionLabelRow.session_id).where(
        SessionLabelRow.classifier == classifier,
        SessionLabelRow.session_id.in_(session_ids),
    )
    return set(db.execute(statement).scalars().all())


def _write(db: DbSession, rows: list[dict[str, object]]) -> None:
    """Upsert labels.

    Keyed on `(session_id, classifier)`, so re-running overwrites this
    classifier's own answer and never touches another's. That is what lets
    the rule engine and three models share one table without co-ordinating.
    """
    statement = insert(SessionLabelRow).values(rows)
    db.execute(
        statement.on_conflict_do_update(
            index_elements=[SessionLabelRow.session_id, SessionLabelRow.classifier],
            set_={
                column: statement.excluded[column]
                for column in rows[0]
                if column not in ("session_id", "classifier")
            },
        )
    )
    logger.info("Wrote %d labels", len(rows))


def classify_pending(
    db: DbSession,
    classifier: Classifier,
    name: str,
    limit: int | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    *,
    reclassify: bool = False,
) -> ClassifyStats:
    """Label every session this classifier owes an answer for."""
    rows = pending_sessions(db, name, limit, reclassify=reclassify)
    logger.info("%d sessions to classify with %s", len(rows), name)
    return classify_sessions(db, classifier, name, rows, batch_size)


#: Above this share of `other` the rules or the taxonomy have a gap, and
#: `docs/taxonomy.md` says which to suspect. Three percent is the figure that
#: document already works to.
OTHER_SHARE_THRESHOLD = 0.03


@dataclass(frozen=True)
class DailyShare:
    """How much of one day a classifier could not label."""

    day: date
    unmatched: int
    total: int

    @property
    def share(self) -> float:
        return self.unmatched / self.total if self.total else 0.0

    @property
    def over_threshold(self) -> bool:
        return self.share > OTHER_SHARE_THRESHOLD

    def __str__(self) -> str:
        flag = "  <-- over threshold" if self.over_threshold else ""
        return f"{self.day}  {self.unmatched:>6} / {self.total:<6} {self.share:6.1%}{flag}"


def daily_unmatched(db: DbSession, classifier: str) -> tuple[DailyShare, ...]:
    """The `other` share per day, oldest first.

    Per day, deliberately. Measured over the whole corpus this number hides
    both failures it exists to catch. A single day of 2,555 unrecognised
    sessions showed up as 8% of three weeks and read like a taxonomy that had
    been broken for weeks; a year later the same campaign would be 0.2% and
    read like nothing at all. Neither is what happened: one day was 39.5% and
    every other day was under 0.3%.

    A campaign is a thing that happens on a date. Averaging over the corpus
    is averaging over the axis the signal lives on.
    """
    day = func.date_trunc("day", SessionRow.started_at)
    unmatched = func.count(SessionLabelRow.session_id).filter(
        SessionLabelRow.intent == str(Intent.OTHER)
    )

    statement = (
        select(day.label("day"), unmatched.label("unmatched"), func.count().label("total"))
        .select_from(SessionRow)
        .join(SessionLabelRow, SessionLabelRow.session_id == SessionRow.session_id)
        .where(SessionLabelRow.classifier == classifier)
        .group_by(day)
        .order_by(day)
    )

    return tuple(
        DailyShare(day=row.day.date(), unmatched=row.unmatched, total=row.total)
        for row in db.execute(statement)
    )
