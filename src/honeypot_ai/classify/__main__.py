"""Classify stored sessions and record the labels.

    python -m honeypot_ai.classify --classifier rules
    python -m honeypot_ai.classify --classifier gemini --limit 200

Safe to re-run: a session already labelled by this classifier under the
current taxonomy is skipped, so the rule engine can run on a timer every few
minutes while a paid model is run deliberately over a bounded number of
sessions.

Each classifier writes under its own name, and they do not overwrite each
other. Running all three leaves three labels per session, which is the
arrangement the evaluation in v0.5.0 needs.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session as DbSession

from honeypot_ai.classify import rules
from honeypot_ai.classify.facts import facts_from_row
from honeypot_ai.classify.llm.classifier import LlmClassifier
from honeypot_ai.classify.llm.gemini import GeminiProvider
from honeypot_ai.classify.llm.ollama import OllamaProvider
from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION
from honeypot_ai.classify.worker import (
    DEFAULT_BATCH_SIZE,
    OTHER_SHARE_THRESHOLD,
    Classifier,
    classify_sessions,
    daily_unmatched,
    pending_sessions,
)
from honeypot_ai.db import SessionRow, session_factory

#: The name the rule engine's labels are stored under. A plain word rather
#: than a version string: the rules live in this repository, so `git log` is
#: the version history, and `--reclassify` is how a change is applied.
RULES = "rules"


def build_classifier(kind: str, model: str | None) -> tuple[Classifier, str]:
    """Return the classifier and the name its labels are stored under.

    The name carries the model for anything hosted or local, so upgrading a
    model starts a new series of labels instead of silently rewriting what the
    previous one concluded.
    """
    if kind == RULES:
        return rules.classify, RULES

    provider = OllamaProvider(model=model) if kind == "ollama" else GeminiProvider(model=model)
    return LlmClassifier(provider).classify, provider.name


def _audit(db: DbSession, name: str) -> int:
    """Report what this classifier could not label, by day.

    By day because a campaign is a thing that happens on a date: averaged over
    the corpus, one day at 39.5% and twenty days at 0.1% come out as 8%, which
    describes neither.
    """
    days = daily_unmatched(db, name)
    if not days:
        print(f"{name}: nothing labelled yet")
        return 0

    print(f"{name}, taxonomy v{TAXONOMY_VERSION}")
    print(f"{'day':<12} {'other':>6} / {'total':<6} {'share':>7}")
    for day in days:
        print(day)

    over = [day for day in days if day.over_threshold]
    if over:
        print(
            f"\n{len(over)} day(s) above {OTHER_SHARE_THRESHOLD:.0%}. Read those sessions:\n"
            "  the commands nobody matched are either rules that under-match or\n"
            "  a category the taxonomy is missing, and docs/taxonomy.md says how\n"
            "  to tell which."
        )
    return 0


def _rehearse(classifier: Classifier, rows: Sequence[SessionRow]) -> int:
    """Print a label per session and write nothing.

    The pipe handling is not incidental. This prints one line per session and
    there are tens of thousands of them, so the obvious way to read it is
    `| head`, and `head` closes the pipe as soon as it has enough. Python then
    raises `BrokenPipeError` on the next write and prints a traceback over the
    output — which looks exactly like the classifier crashing on session 20.

    Tools that produce unbounded output have to expect to be piped into
    something that stops listening. That is a normal end to a command, not an
    error, so it exits quietly.
    """
    try:
        for row in rows:
            label = classifier(facts_from_row(row))
            behaviours = ", ".join(sorted(str(b) for b in label.behaviours)) or "—"
            print(f"  {row.session_id}  {label.intent}  [{behaviours}]")
        print(f"\nDry run: {len(rows)} session(s) classified, nothing written.")
    except BrokenPipeError:
        # Whatever was reading has gone. Point stdout at /dev/null so the
        # interpreter's own flush at exit does not raise this again, and say
        # nothing further.
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.classify",
        description="Label stored sessions with intent, behaviours and operator.",
    )
    parser.add_argument(
        "--classifier",
        choices=[RULES, "gemini", "ollama"],
        default=RULES,
        help="which classifier to run (default: rules)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="override the model, for the gemini and ollama classifiers",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="label at most this many sessions, newest first",
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument(
        "--reclassify",
        action="store_true",
        help="relabel sessions this classifier has already answered for, "
        "for when the rules or the prompt changed rather than the taxonomy",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="report the share of sessions this classifier could not label, "
        "per day, and flag the days over threshold",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="classify and print, write nothing",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    if args.classifier == "gemini" and not os.getenv("GEMINI_API_KEY"):
        print("GEMINI_API_KEY is not set.", file=sys.stderr)
        return 2

    classifier, name = build_classifier(args.classifier, args.model)

    if args.audit:
        with session_factory()() as db:
            return _audit(db, name)

    with session_factory()() as db:
        rows = pending_sessions(db, name, args.limit, reclassify=args.reclassify)
        print(f"{name}, taxonomy v{TAXONOMY_VERSION}: {len(rows)} session(s) to label")

        if args.dry_run:
            return _rehearse(classifier, rows)

        stats = classify_sessions(db, classifier, name, rows, args.batch_size)

    print(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
