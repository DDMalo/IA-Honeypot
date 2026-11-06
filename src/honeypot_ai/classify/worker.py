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
from datetime import date, datetime

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import selectinload

from honeypot_ai.classify.facts import SessionFacts, facts_from_row
from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION, Intent, Label
from honeypot_ai.db import SessionLabelRow, SessionRow
from honeypot_ai.db.limits import in_chunks

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
    replaced: int = 0
    unclassified: int = 0
    failed: int = 0

    def __str__(self) -> str:
        parts = [f"{self.pending} sessions pending", f"{self.labelled} labelled"]
        if self.replaced:
            # Deliberately says what happened, not why. This counter knows the
            # session had a label before and nothing else: the cause may be a
            # taxonomy change or an explicit --reclassify, and asserting the
            # wrong one in a line somebody reads as a result is how a figure
            # starts being quoted as something it is not.
            parts.append(f"{self.replaced} replacing an earlier label")
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
            stats.replaced += 1
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
    found: set[str] = set()

    # Split, because the list is as long as the run: 115,353 sessions put
    # 115,354 bind parameters into one `IN (...)` and the statement was
    # refused outright. The same limit had just been fixed in ingestion, in
    # a different shape, which is why it now lives in one place.
    for chunk in in_chunks(session_ids):
        statement = select(SessionLabelRow.session_id).where(
            SessionLabelRow.classifier == classifier,
            SessionLabelRow.session_id.in_(chunk),
        )
        found.update(db.execute(statement).scalars().all())

    return found


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


# --- One answer per distinct sequence ---------------------------------------
#
# The corpus is mostly repetition: one campaign was 2,555 sessions of the same
# command, and a month of 156,739 sessions held only 950 distinct sequences. A
# language model asked about every session would be asked the same question
# thousands of times and charged for each. Grouping by sequence asks once and
# writes the answer to every session that shared it, which turns a quota that
# could never keep up into one that is mostly idle.
#
# The grouping key is the one the evaluation sample uses — the exact command
# sequence plus whether the login succeeded — so "a sequence" means the same
# thing in the evaluation and in production. That is also what makes the
# reuse sound: a classifier sees only the commands and the login outcome, so
# two sessions with the same key are, to it, the same input.

#: Every session with its sequence key and whether this classifier has a
#: current label for it. `md5` is a grouping key, not a security control.
_SEQUENCES = text(
    """
    WITH fingerprints AS (
        SELECT s.session_id,
               s.started_at,
               md5(
                   coalesce(string_agg(c.input, E'\\n' ORDER BY c.seq), '')
                   || '|' || s.authenticated::text
               ) AS fingerprint
        FROM sessions s
        LEFT JOIN commands c ON c.session_id = s.session_id
        GROUP BY s.session_id, s.started_at, s.authenticated
    )
    SELECT f.fingerprint, f.session_id, f.started_at, l.session_id IS NOT NULL AS labelled
    FROM fingerprints f
    LEFT JOIN session_labels l
      ON l.session_id = f.session_id
     AND l.classifier = :classifier
     AND l.taxonomy_version = :version
    """
)


@dataclass
class SequenceStats:
    """What a by-sequence run did, in the units that cost something."""

    sequences_pending: int = 0
    model_calls: int = 0
    reused: int = 0
    sessions_labelled: int = 0
    unclassified: int = 0
    failed: int = 0
    left_for_later: int = 0

    def __str__(self) -> str:
        parts = [
            f"{self.sequences_pending} sequences pending",
            f"{self.model_calls} classified",
            f"{self.reused} answered from an earlier label",
            f"{self.sessions_labelled} sessions labelled",
        ]
        if self.unclassified:
            parts.append(f"{self.unclassified} unclassified, to retry")
        if self.failed:
            parts.append(f"{self.failed} failed")
        if self.left_for_later:
            parts.append(f"{self.left_for_later} left for the next run")
        return ", ".join(parts)


@dataclass
class _Group:
    fingerprint: str
    newest: datetime
    pending: list[str]
    labelled: list[str]


def _pending_groups(db: DbSession, classifier: str) -> list[_Group]:
    """Sequences with at least one session still owed a label, newest first."""
    groups: dict[str, _Group] = {}
    rows = db.execute(_SEQUENCES, {"classifier": classifier, "version": TAXONOMY_VERSION})
    for row in rows:
        group = groups.setdefault(row.fingerprint, _Group(row.fingerprint, row.started_at, [], []))
        (group.labelled if row.labelled else group.pending).append(row.session_id)
        if row.started_at > group.newest:
            group.newest = row.started_at
    pending = [group for group in groups.values() if group.pending]
    # Newest first, like the per-session worker: a run cut short by a quota
    # leaves the most recent traffic labelled. Ties broken by key, so the
    # order does not depend on how the database returned the rows.
    return sorted(pending, key=lambda g: (g.newest, g.fingerprint), reverse=True)


def classify_by_sequence(
    db: DbSession,
    classifier: Classifier,
    name: str,
    max_calls: int | None = None,
) -> SequenceStats:
    """Label every pending session, calling the classifier once per sequence.

    A sequence this classifier has already answered for, under the current
    taxonomy, is not asked again: the existing answer is copied to the new
    sessions that share it. `max_calls` bounds the classifier calls, not the
    sessions, because the calls are what a quota counts.

    A sequence the classifier declines to answer is not written. Storing the
    refusal would mark every session sharing it as done and it would never be
    asked again; leaving it pending means the next run retries it, and the
    call limit stops a sequence that always fails from eating the quota.
    """
    groups = _pending_groups(db, name)
    stats = SequenceStats(sequences_pending=len(groups))

    for group in groups:
        if group.labelled:
            source = db.get(SessionLabelRow, (min(group.labelled), name))
            if source is None:  # deleted between the read and now
                continue
            writes = [
                _row(
                    session_id,
                    name,
                    source.intent,
                    source.behaviours,
                    source.operator,
                    source.confidence,
                    source.rationale,
                )
                for session_id in group.pending
            ]
            stats.reused += 1
        else:
            if max_calls is not None and stats.model_calls >= max_calls:
                stats.left_for_later += 1
                continue
            # Any member will do: to the classifier they are the same input.
            representative = _load_session(db, min(group.pending))
            stats.model_calls += 1
            try:
                label = classifier(facts_from_row(representative))
            except Exception:
                logger.exception("Classifier %s failed on sequence %s", name, group.fingerprint)
                stats.failed += 1
                continue
            if label.intent is Intent.OTHER and label.confidence == 0.0:
                stats.unclassified += 1
                continue
            writes = [
                _row(
                    session_id,
                    name,
                    str(label.intent),
                    sorted(str(b) for b in label.behaviours),
                    str(label.operator),
                    label.confidence,
                    label.notes,
                )
                for session_id in group.pending
            ]

        for chunk_start in range(0, len(writes), DEFAULT_BATCH_SIZE):
            _write(db, writes[chunk_start : chunk_start + DEFAULT_BATCH_SIZE])
        db.commit()
        stats.sessions_labelled += len(writes)

    return stats


def _load_session(db: DbSession, session_id: str) -> SessionRow:
    statement = (
        select(SessionRow)
        .where(SessionRow.session_id == session_id)
        .options(
            selectinload(SessionRow.commands),
            selectinload(SessionRow.login_attempts),
            selectinload(SessionRow.file_transfers),
        )
    )
    return db.execute(statement).scalar_one()


def _row(
    session_id: str,
    classifier: str,
    intent: str,
    behaviours: Sequence[str],
    operator: str,
    confidence: float | None,
    rationale: str | None,
) -> dict[str, object]:
    return {
        "session_id": session_id,
        "classifier": classifier,
        "intent": intent,
        "behaviours": list(behaviours),
        "operator": operator,
        "confidence": confidence,
        "rationale": rationale,
        "taxonomy_version": TAXONOMY_VERSION,
    }


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
