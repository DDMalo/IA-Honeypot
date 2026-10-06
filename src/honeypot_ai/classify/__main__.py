"""Run the rule engine over the stored sessions and report what it found.

    python -m honeypot_ai.classify
    python -m honeypot_ai.classify --unmatched 20

**Nothing is written.** Storing classifications is a later card; this exists so
the rules can be checked against the real corpus while they are being written,
and so the baseline distribution is a number rather than an impression.

The figure to watch is not the headline distribution — on this data that is
dominated by one class whatever the rules do — but the sessions where no rule
matched. Those are either a gap in the rules or a gap in the taxonomy, and
`--unmatched` prints them so the difference can be told by reading.
"""

from __future__ import annotations

import argparse
import logging
from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from honeypot_ai.classify.facts import facts_from_row
from honeypot_ai.classify.rules import classify
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Operator
from honeypot_ai.db import SessionRow, session_factory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.classify",
        description="Apply the rule engine to stored sessions and report the result. "
        "Reads only; nothing is written.",
    )
    parser.add_argument("--limit", type=int, default=None, help="classify at most this many")
    parser.add_argument(
        "--unmatched",
        type=int,
        default=0,
        metavar="N",
        help="also print N sessions no rule recognised",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    intents: Counter[Intent] = Counter()
    behaviours: Counter[Behaviour] = Counter()
    operators: Counter[Operator] = Counter()
    coverage_total = 0.0
    unmatched: list[tuple[str, tuple[str, ...]]] = []
    total = 0

    statement = select(SessionRow).options(
        selectinload(SessionRow.commands),
        selectinload(SessionRow.file_transfers),
    )
    if args.limit is not None:
        statement = statement.limit(args.limit)

    with session_factory()() as db:
        for row in db.scalars(statement).all():
            facts = facts_from_row(row)
            label = classify(facts)

            total += 1
            intents[label.intent] += 1
            operators[label.operator] += 1
            behaviours.update(label.behaviours)
            coverage_total += label.confidence or 0.0

            if not label.behaviours and facts.commands and len(unmatched) < args.unmatched:
                unmatched.append((facts.session_id, facts.commands))

    if not total:
        print("No sessions in the database.")
        return 0

    print(f"{total} sessions\n")

    print("Intent")
    for intent, count in intents.most_common():
        print(f"  {intent.value:<20} {count:>6}  {count / total:>6.1%}")

    majority = intents.most_common(1)[0]
    print(
        f"\n  Always answering {majority[0].value!r} would score "
        f"{majority[1] / total:.1%} accuracy while knowing nothing.\n"
        "  That is the floor any classifier has to beat, and the reason this\n"
        "  project reports macro-averaged F1 instead.\n"
    )

    print("Behaviour")
    for behaviour, count in behaviours.most_common():
        print(f"  {behaviour.value:<24} {count:>6}")

    print("\nOperator")
    for operator, count in operators.most_common():
        print(f"  {operator.value:<20} {count:>6}")

    print(f"\nMean rule coverage: {coverage_total / total:.1%}")

    if unmatched:
        print(f"\nSessions no rule recognised (showing {len(unmatched)}):")
        for session_id, commands in unmatched:
            print(f"\n  {session_id}")
            for command in commands[:8]:
                print(f"    {command[:160]}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
