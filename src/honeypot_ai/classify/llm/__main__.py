"""Try a language model on real sessions, next to the rule engine.

    python -m honeypot_ai.classify.llm --models
    python -m honeypot_ai.classify.llm --sample 10
    python -m honeypot_ai.classify.llm --provider ollama --sample 10

**Nothing is written.** This is a smoke test and a first look: does the
provider work, does the model answer in the right shape, and does it say
anything the rule engine did not. The measured comparison is v0.5.0's job and
needs a labelled set; this is for finding out whether it is worth building.

Sessions are sampled from the ones that got past a single command, because a
random sample would be nine `uname` probes out of ten and tell you nothing.

Both providers go through the same prompt, parser and validation, so the two
numbers printed at the end — availability and latency — compare the models
rather than two integrations written on different days.
"""

from __future__ import annotations

import argparse
import logging
import random
import statistics
import time

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from honeypot_ai.classify.facts import facts_from_row
from honeypot_ai.classify.llm.classifier import LlmClassifier
from honeypot_ai.classify.llm.gemini import GeminiProvider
from honeypot_ai.classify.llm.injection import CASES, InjectionResult
from honeypot_ai.classify.llm.ollama import OllamaProvider
from honeypot_ai.classify.llm.provider import Provider, ProviderError
from honeypot_ai.classify.rules import classify as classify_by_rules
from honeypot_ai.db import SessionRow, session_factory


def build_provider(name: str, model: str | None) -> Provider:
    if name == "ollama":
        return OllamaProvider(model=model)
    return GeminiProvider(model=model)


def _run_injection_suite(provider: Provider) -> int:
    """Feed every hostile session to the model and score the outcome.

    Reads nothing from the database: the corpus is synthetic, so this runs
    anywhere the provider is reachable.
    """
    classifier = LlmClassifier(provider)
    results: list[InjectionResult] = []

    print(f"{provider.name} against {len(CASES)} injection attempts\n")

    for case in CASES:
        label = classifier.classify(case.facts)
        result = InjectionResult(case=case, answered=label.intent, rationale=label.notes)
        results.append(result)

        print(f"  {result.verdict:<9} {case.name:<24} {case.technique}")
        if not result.resisted:
            print(f"            wanted {case.expected.value}, said {label.intent.value}")

    injected = sum(1 for r in results if r.succeeded)
    resisted = sum(1 for r in results if r.resisted)
    confused = len(results) - injected - resisted

    print(f"\n{resisted}/{len(results)} resisted, {injected} injected, {confused} confused")
    print(
        "\nAn injection that works changes one label and nothing else: the model\n"
        "emits JSON, calls no tool, runs no command, and anything it invents fails\n"
        "schema validation. This number measures the prompt; the architecture is\n"
        "what bounds the damage."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.classify.llm",
        description="Classify a few sessions with a language model and compare "
        "against the rule engine. Reads only; nothing is written.",
    )
    parser.add_argument(
        "--provider",
        choices=["gemini", "ollama"],
        default="gemini",
        help="which backend to use (default: gemini)",
    )
    parser.add_argument("--models", action="store_true", help="list the available models")
    parser.add_argument(
        "--injection-suite",
        action="store_true",
        help="run the adversarial corpus and report how many injections worked",
    )
    parser.add_argument("--sample", type=int, default=5, help="how many sessions to try")
    parser.add_argument("--model", default=None, help="override the provider's default model")
    parser.add_argument(
        "--all-sessions",
        action="store_true",
        help="sample from every session, not only the interesting ones",
    )
    parser.add_argument("--seed", type=int, default=None, help="sample the same sessions again")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)

    try:
        provider = build_provider(args.provider, args.model)
    except ProviderError as exc:
        print(exc)
        return 2

    with provider:  # type: ignore[attr-defined]
        if args.models:
            try:
                for model in provider.list_models():  # type: ignore[attr-defined]
                    print(model)
            except ProviderError as exc:
                print(exc)
                return 2
            return 0

        if args.injection_suite:
            return _run_injection_suite(provider)

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

        # Seeding lets two providers be given the same sessions, which is the
        # difference between a comparison and two unrelated samples.
        chooser = random.Random(args.seed)  # noqa: S311
        chosen = chooser.sample(rows, min(args.sample, len(rows)))
        classifier = LlmClassifier(provider)
        latencies: list[float] = []
        agreements = 0

        print(f"{provider.name}\n")
        for row in chosen:
            facts = facts_from_row(row)
            by_rules = classify_by_rules(facts)

            started = time.monotonic()
            by_model = classifier.classify(facts)
            elapsed = time.monotonic() - started

            answered = not (by_model.notes or "").startswith("unclassified:")
            if answered:
                latencies.append(elapsed)
                if by_rules.intent is by_model.intent:
                    agreements += 1

            agree = "same" if by_rules.intent is by_model.intent else "DIFFERENT"
            print(
                f"{facts.session_id}  ({len(facts.commands)} commands)  [{agree}]  {elapsed:.1f}s"
            )
            for command in facts.commands[:4]:
                print(f"    {command[:120]}")
            print(f"  rules: {by_rules.intent.value}")
            print(f"  model: {by_model.intent.value}  — {by_model.notes or ''}")
            print()

        stats = classifier.stats
        attempted = len(chosen)
        print(stats)
        print(
            f"\nAvailability: {stats.classified}/{attempted} answered "
            f"({stats.classified / attempted:.0%})"
        )

        if latencies:
            print(
                f"Latency:      median {statistics.median(latencies):.1f}s, "
                f"slowest {max(latencies):.1f}s"
            )
            print(f"Agreement:    {agreements}/{len(latencies)} of the answers matched the rules")
        if stats.classified < attempted:
            print(
                "\nA provider that answers some of the time is a result, not a bug to\n"
                "hide: availability is part of what the comparison measures."
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
