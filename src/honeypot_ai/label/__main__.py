"""Build the evaluation set and label it.

    python -m honeypot_ai.label sample --per-class 20 --uniform 60 --seed 1
    python -m honeypot_ai.label review --labeller david
    python -m honeypot_ai.label status

`sample` needs the database and writes `eval/sample.jsonl`, anonymised and
safe to commit. `review` and `status` need nothing but that file, so labelling
can happen on any machine with a copy of the repository — the laptop on a
train, without the homelab switched on.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from honeypot_ai.classify.taxonomy import TAXONOMY_VERSION
from honeypot_ai.label.review import review
from honeypot_ai.label.store import (
    DEFAULT_LABELS,
    DEFAULT_META,
    DEFAULT_SAMPLE,
    latest,
    now,
    read_labels,
    read_sample,
    write_sample,
)


def _sample(args: argparse.Namespace) -> int:
    if args.out.exists() and not args.force:
        print(
            f"{args.out} already exists. Redrawing the sample orphans every label\n"
            "written against it, so it is refused without --force.",
            file=sys.stderr,
        )
        return 2

    from honeypot_ai.db import session_factory
    from honeypot_ai.label.sample import build_sample

    with session_factory()() as db:
        items, population = build_sample(
            db, per_class=args.per_class, uniform=args.uniform, seed=args.seed
        )

    written = write_sample(items, args.out)

    by_stratum: Counter[str] = Counter()
    sessions_by_stratum: Counter[str] = Counter()
    for candidate in population:
        by_stratum[candidate.stratum.value] += 1
        sessions_by_stratum[candidate.stratum.value] += candidate.sessions

    meta = {
        "created": now().isoformat(),
        "seed": args.seed,
        "per_class": args.per_class,
        "uniform": args.uniform,
        "taxonomy_version": TAXONOMY_VERSION,
        "items": written,
        "population": {
            "sessions": sum(sessions_by_stratum.values()),
            "sequences": len(population),
            "sequences_by_stratum": dict(sorted(by_stratum.items())),
            "sessions_by_stratum": dict(sorted(sessions_by_stratum.items())),
        },
        "drawn_by": dict(Counter(item.drawn_by.value for item in items)),
    }
    args.meta.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    print(
        f"{written} items written to {args.out}, from "
        f"{meta['population']['sequences']} distinct sequences across "
        f"{meta['population']['sessions']} sessions."
    )
    print(f"Population recorded in {args.meta}. Both are anonymised and meant to be committed.")
    return 0


def _review(args: argparse.Namespace) -> int:
    if not args.sample.exists():
        print(f"No sample at {args.sample}; run `sample` first.", file=sys.stderr)
        return 2

    items = read_sample(args.sample)
    done = set(latest(read_labels(args.labels), labeller=args.labeller))

    print(f"{len(items)} items, {len(done)} already labelled by {args.labeller}.")
    print("Type ? at any prompt for the definitions. s skips, q stops; every answer is saved.")

    try:
        stats = review(items, done, args.labeller, input, print, args.labels)
    except (KeyboardInterrupt, EOFError):
        print("\nStopped. Everything answered so far is saved.")
        return 0

    print(f"\n{stats}")
    return 0


def _status(args: argparse.Namespace) -> int:
    if not args.sample.exists():
        print(f"No sample at {args.sample}.", file=sys.stderr)
        return 2

    items = read_sample(args.sample)
    labels = read_labels(args.labels)
    labellers = sorted({label.labeller for label in labels})

    print(f"{len(items)} items in the sample")
    for labeller in labellers or ["(nobody yet)"]:
        current = latest(labels, labeller=labeller)
        by_part = Counter(item.drawn_by.value for item in items if item.sample_id in current)
        parts = ", ".join(f"{count} {part}" for part, count in sorted(by_part.items()))
        print(
            f"  {labeller}: {len(current)}/{len(items)} labelled" + (f" ({parts})" if parts else "")
        )

    stale = [label for label in labels if label.taxonomy_version != TAXONOMY_VERSION]
    if stale:
        print(
            f"\n{len(stale)} label(s) were written under an older taxonomy and will be "
            "ignored by the evaluation."
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m honeypot_ai.label")
    commands = parser.add_subparsers(dest="command", required=True)

    sample = commands.add_parser("sample", help="draw the evaluation sample from the database")
    sample.add_argument("--per-class", type=int, default=20)
    sample.add_argument("--uniform", type=int, default=60)
    sample.add_argument("--seed", type=int, default=1)
    sample.add_argument("--out", type=Path, default=DEFAULT_SAMPLE)
    sample.add_argument("--meta", type=Path, default=DEFAULT_META)
    sample.add_argument("--force", action="store_true", help="overwrite an existing sample")
    sample.set_defaults(run=_sample)

    rev = commands.add_parser("review", help="label the sample, blind")
    rev.add_argument("--labeller", required=True, help="your name, recorded on every label")
    rev.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    rev.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    rev.set_defaults(run=_review)

    status = commands.add_parser("status", help="how far the labelling has got")
    status.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    status.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    status.set_defaults(run=_status)

    args = parser.parse_args(argv)
    return int(args.run(args))


if __name__ == "__main__":
    raise SystemExit(main())
