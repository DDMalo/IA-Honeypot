"""Choose which sessions a person should label.

Three decisions, each of which would quietly ruin the evaluation if made the
other way.

**Distinct sequences, not sessions.** The corpus is dominated by repetition:
one campaign was 2,555 sessions of the same single command. Labelling thirty
copies of it is thirty labels' worth of effort spent learning one thing. So
sessions are grouped by a fingerprint of what they did — the exact command
sequence plus whether the login succeeded — and one representative of each
group is a candidate. The group's size is kept as the item's *weight*, so the
evaluation can report both "how often is the classifier right about a kind of
behaviour" and "how often is it right about a session", which are different
numbers and both matter.

**Two components, for two different questions.** A sample drawn only at
random over sessions would be about two-thirds `fingerprinting` and contain a
couple of `persistence` sessions at best, so per-class precision for the rare
classes would rest on one or two labels. A sample drawn only by class gives
every class coverage but describes no real population. This takes both:

* a **uniform** part, drawn with probability proportional to how many sessions
  share each sequence — an unbiased picture of what actually arrives;
* a **stratified** part, a fixed number of distinct sequences per class, which
  guarantees every class has enough labels to say something about.

Each item records which part drew it, and the evaluation keeps them apart.

**Strata come from the rule engine, and that has a cost.** The only label
available before anyone has labelled anything is the rules' own. Sampling by
it gives an unbiased estimate of the rules' *precision* in each class —
everything they called `staging` had an equal chance of being drawn — but a
biased estimate of their *recall*, because a session the rules put in the
wrong class was sampled from that wrong class. The uniform part does not have
this problem, which is the other reason it exists. Written down here because
it is exactly the kind of caveat that gets lost between the code and the
results table.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import select, text
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import selectinload

from honeypot_ai.classify.facts import SessionFacts, facts_from_row
from honeypot_ai.classify.taxonomy import Intent
from honeypot_ai.db import SessionRow
from honeypot_ai.db.limits import in_chunks
from honeypot_ai.label.anonymise import Anonymiser


class DrawnBy(StrEnum):
    UNIFORM = "uniform"
    STRATUM = "stratum"


@dataclass(frozen=True)
class Candidate:
    """One distinct thing attackers did, and how often they did it."""

    fingerprint: str
    stratum: Intent
    """What the rule engine called it. Used to stratify, never shown to the labeller."""
    sessions: int
    representative: str


@dataclass(frozen=True)
class SampleItem:
    """One item to label: a representative session, anonymised."""

    sample_id: str
    session_id: str
    stratum: Intent
    weight: int
    drawn_by: DrawnBy
    facts: SessionFacts


def choose(
    candidates: Sequence[Candidate],
    *,
    per_class: int,
    uniform: int,
    seed: int,
) -> list[tuple[Candidate, DrawnBy]]:
    """Pick the items to label. Pure, seeded, and independent of input order.

    The uniform part is drawn first and weighted by session count, using the
    Efraimidis–Spirakis method so that weighted sampling without replacement
    stays exact and reproducible. The stratified part then fills each class up
    to `per_class` from sequences not already chosen, uniformly over
    sequences, which favours variety over repetition.

    The result is shuffled. A labeller shown every `staging` session in a row
    starts labelling the run rather than the session.
    """
    # Seeded on purpose: the sample has to be reproducible, which is the
    # opposite of what a cryptographic generator is for.
    rng = random.Random(seed)  # noqa: S311
    # Sorted, so the database's row order cannot change the sample.
    pool = sorted(candidates, key=lambda c: (c.fingerprint, c.stratum.value))

    keyed = sorted(
        ((rng.random() ** (1.0 / c.sessions), c) for c in pool if c.sessions > 0),
        key=lambda pair: pair[0],
        reverse=True,
    )
    chosen: list[tuple[Candidate, DrawnBy]] = []
    taken: set[str] = set()
    for _, candidate in keyed:
        if len(chosen) >= uniform:
            break
        # A sequence the rules labelled two ways appears twice in the pool;
        # it is still one thing to label.
        if candidate.fingerprint not in taken:
            chosen.append((candidate, DrawnBy.UNIFORM))
            taken.add(candidate.fingerprint)

    by_class: defaultdict[Intent, list[Candidate]] = defaultdict(list)
    for candidate in pool:
        if candidate.fingerprint not in taken:
            by_class[candidate.stratum].append(candidate)

    for intent in sorted(by_class, key=lambda i: i.value):
        already = sum(1 for c, _ in chosen if c.stratum is intent)
        need = max(0, per_class - already)
        group = by_class[intent]
        for candidate in rng.sample(group, min(need, len(group))):
            chosen.append((candidate, DrawnBy.STRATUM))
            taken.add(candidate.fingerprint)

    rng.shuffle(chosen)
    return chosen


#: One row per distinct (sequence, rule label). `md5` here is a grouping key,
#: not a security control: it only has to make equal sequences collide.
_CANDIDATES = text(
    """
    WITH fingerprints AS (
        SELECT s.session_id,
               md5(
                   coalesce(string_agg(c.input, E'\\n' ORDER BY c.seq), '')
                   || '|' || s.authenticated::text
               ) AS fingerprint
        FROM sessions s
        LEFT JOIN commands c ON c.session_id = s.session_id
        GROUP BY s.session_id, s.authenticated
    )
    SELECT f.fingerprint,
           l.intent,
           count(*) AS sessions,
           min(f.session_id) AS representative
    FROM fingerprints f
    JOIN session_labels l
      ON l.session_id = f.session_id AND l.classifier = :classifier
    GROUP BY f.fingerprint, l.intent
    """
)


def load_candidates(db: DbSession, classifier: str = "rules") -> list[Candidate]:
    """Every distinct sequence the rule engine has labelled, with its weight."""
    rows = db.execute(_CANDIDATES, {"classifier": classifier}).all()
    return [
        Candidate(
            fingerprint=row.fingerprint,
            stratum=Intent(row.intent),
            sessions=row.sessions,
            representative=row.representative,
        )
        for row in rows
    ]


def build_sample(
    db: DbSession,
    *,
    per_class: int,
    uniform: int,
    seed: int,
) -> tuple[list[SampleItem], list[Candidate]]:
    """Draw a sample and return it anonymised, with the population it came from."""
    candidates = load_candidates(db)
    picked = choose(candidates, per_class=per_class, uniform=uniform, seed=seed)

    ids = [candidate.representative for candidate, _ in picked]
    rows: dict[str, SessionRow] = {}
    for chunk in in_chunks(ids):
        statement = (
            select(SessionRow)
            .where(SessionRow.session_id.in_(chunk))
            .options(
                selectinload(SessionRow.commands),
                selectinload(SessionRow.login_attempts),
                selectinload(SessionRow.file_transfers),
            )
        )
        rows.update({row.session_id: row for row in db.execute(statement).scalars()})

    # One anonymiser for the whole export, fed in sample order, so the same
    # server gets the same placeholder everywhere and the export is stable.
    anonymiser = Anonymiser()
    items = [
        SampleItem(
            sample_id=candidate.fingerprint[:12],
            session_id=candidate.representative,
            stratum=candidate.stratum,
            weight=candidate.sessions,
            drawn_by=drawn_by,
            facts=anonymiser.facts(facts_from_row(rows[candidate.representative])),
        )
        for candidate, drawn_by in picked
    ]
    return items, candidates
