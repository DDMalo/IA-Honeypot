"""Try the language model on a handful of real sessions, next to the rules.

    python -m honeypot_ai.classify.llm --models
    python -m honeypot_ai.classify.llm --sample 5

**Nothing is written.** This is a smoke test and a first look: does the key
work, does the model answer in the right shape, and does it say anything the
rule engine did not. The measured comparison is v0.5.0's job and needs a
labelled set; this is for finding out whether it is worth building.

Sessions are sampled from the ones the rules found most interesting — any
session that got past fingerprinting — because a random sample would be nine
`uname` probes out of ten and tell you nothing.
"""

from __future__ import annotations

import argparse
import logging
import random

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from honeypot_ai.classify.facts import facts_from_row
from honeypot_ai.classify.llm.classifier import LlmClassifier
from honeypot_ai.classify.llm.gemini import GeminiProvider
from honeypot_ai.classify.llm.provider import ProviderError
from honeypot_ai.classify.rules import classify as classify_by_rules
from honeypot_ai.db import SessionRow, session_factory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.classify.llm",
        description="Classify a few sessions with Gemini and compare against the rules.",
    )
    parser.add_argument("--models", action="store_true", help="list the models this key can use")
    parser.add_argument("--sample", type=int, default=5, help="how many sessions to try")
    parser.add_argument("--model", default=None, help="override GEMINI_MODEL")
    parser.add_argument(
        "--all-sessions",
        action="store_true",
        help="sample from every session, not only the interesting ones",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        provider = GeminiProvider(model=args.model)
    except ProviderError as exc:
        print(exc)
        return 2

    with provider:
        if args.models:
            try:
                for model in provider.list_models():
                    print(model)
            except ProviderError as exc:
                print(exc)
                return 2
            return 0

        statement = select(SessionRow).options(
            selectinload(SessionRow.commands),
            selectinload(SessionRow.file_transfers),
        )
        if not args.all_sessions:
            statement = statement.where(SessionRow.command_count > 1)

        with session_factory()() as db:
            rows = list(db.scalars(statement).all())

        if not rows:
            print("No sessions to classify.")
            return 0

        chosen = random.sample(rows, min(args.sample, len(rows)))  # noqa: S311
        classifier = LlmClassifier(provider)

        print(f"{provider.name}\n")
        for row in chosen:
            facts = facts_from_row(row)
            by_rules = classify_by_rules(facts)
            by_model = classifier.classify(facts)

            agree = "same" if by_rules.intent is by_model.intent else "DIFFERENT"
            print(f"{facts.session_id}  ({len(facts.commands)} commands)  [{agree}]")
            for command in facts.commands[:4]:
                print(f"    {command[:120]}")
            print(f"  rules: {by_rules.intent.value}")
            print(f"  model: {by_model.intent.value}  — {by_model.notes or ''}")
            print()

        print(classifier.stats)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
