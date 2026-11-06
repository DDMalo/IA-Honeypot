"""Score the classifiers against the labelled evaluation set.

    python -m honeypot_ai.evaluate predict --classifier rules
    python -m honeypot_ai.evaluate predict --classifier gemini [--model M] [--limit N]
    python -m honeypot_ai.evaluate predict --classifier ollama [--model M]
    python -m honeypot_ai.evaluate report eval/predictions/*.jsonl [--out eval/results.md]

Neither command needs the database: both read `eval/sample.jsonl`, so anyone
with a copy of the repository can re-score the published predictions, and
anyone with a key can reproduce them.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from honeypot_ai.classify import rules
from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.evaluate.predict import (
    DEFAULT_DIR,
    Classify,
    file_for,
    latest_predictions,
    predict,
    read_predictions,
)
from honeypot_ai.evaluate.report import DEFAULT_REFERENCE, Pricing, build_report
from honeypot_ai.label.store import (
    DEFAULT_LABELS,
    DEFAULT_META,
    DEFAULT_SAMPLE,
    read_labels,
    read_sample,
)


def build(kind: str, model: str | None) -> tuple[Classify, str, Callable[[SessionFacts], int]]:
    """The classifier, the name it is recorded under, and its prompt size."""
    if kind == "rules":
        return rules.classify, "rules", lambda _facts: 0

    from honeypot_ai.classify.llm import SYSTEM_PROMPT, build_user_prompt
    from honeypot_ai.classify.llm.classifier import LlmClassifier
    from honeypot_ai.classify.llm.gemini import GeminiProvider
    from honeypot_ai.classify.llm.ollama import OllamaProvider

    provider = OllamaProvider(model=model) if kind == "ollama" else GeminiProvider(model=model)

    def size(facts: SessionFacts) -> int:
        return len(SYSTEM_PROMPT) + len(build_user_prompt(facts))

    return LlmClassifier(provider).classify, provider.name, size


def _predict(args: argparse.Namespace) -> int:
    items = read_sample(args.sample)
    classify, name, size = build(args.classifier, args.model)
    path = file_for(name, args.dir)
    print(f"{name}: {len(items)} items, predictions in {path}")

    def show(prediction: object) -> None:
        print(".", end="", flush=True)

    try:
        made = predict(
            items, classify, name, path, prompt_size=size, limit=args.limit, on_item=show
        )
    except KeyboardInterrupt:
        print("\nStopped. Every prediction made so far is saved; run again to resume.")
        return 0
    print(f"\n{made} new prediction(s).")
    return 0


def _report(args: argparse.Namespace) -> int:
    items = read_sample(args.sample)
    labels = read_labels(args.labels)
    meta = json.loads(args.meta.read_text(encoding="utf-8")) if args.meta.exists() else None

    runs = {}
    for path in args.predictions:
        predictions = read_predictions(path)
        names = {p.classifier for p in predictions}
        if len(names) != 1:
            print(
                f"{path}: expected one classifier, found {sorted(names) or 'none'}", file=sys.stderr
            )
            return 2
        runs[names.pop()] = latest_predictions(predictions)

    pricing = Pricing(args.price_in, args.price_out, args.output_tokens)
    try:
        text = build_report(items, labels, runs, meta, reference=args.reference, pricing=pricing)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2

    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"Written to {args.out}")
    else:
        print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m honeypot_ai.evaluate")
    commands = parser.add_subparsers(dest="command", required=True)

    pred = commands.add_parser("predict", help="run a classifier over the sample")
    pred.add_argument("--classifier", choices=["rules", "gemini", "ollama"], required=True)
    pred.add_argument("--model", default=None, help="model name; defaults to the configured one")
    pred.add_argument("--limit", type=int, default=None, help="stop after this many new items")
    pred.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    pred.add_argument("--dir", type=Path, default=DEFAULT_DIR)
    pred.set_defaults(run=_predict)

    rep = commands.add_parser("report", help="score predictions against the reference")
    rep.add_argument("predictions", type=Path, nargs="+")
    rep.add_argument("--reference", default=DEFAULT_REFERENCE)
    rep.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    rep.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    rep.add_argument("--meta", type=Path, default=DEFAULT_META)
    rep.add_argument("--out", type=Path, default=None)
    rep.add_argument("--price-in", type=float, default=0.0, help="USD per million input tokens")
    rep.add_argument("--price-out", type=float, default=0.0, help="USD per million output tokens")
    rep.add_argument("--output-tokens", type=int, default=150, help="assumed output per item")
    rep.set_defaults(run=_report)

    args = parser.parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    sys.exit(main())
