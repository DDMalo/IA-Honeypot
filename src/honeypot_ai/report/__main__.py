"""Write the weekly report.

    python -m honeypot_ai.report weekly                    # the last complete week
    python -m honeypot_ai.report weekly --week 2026-W45    # a given ISO week
    python -m honeypot_ai.report weekly --notify           # and a summary to ntfy

Written to `reports/weekly-<week>.md`. The files are aggregates and safe to
publish under the privacy notes, but they are not committed automatically:
which ones go into the repository is a decision for a person.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from honeypot_ai.report.weekly import Week, gather, render, summary

DEFAULT_DIR = Path("reports")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m honeypot_ai.report")
    commands = parser.add_subparsers(dest="command", required=True)
    weekly = commands.add_parser("weekly", help="report one ISO week")
    weekly.add_argument("--week", default=None, help="e.g. 2026-W45; default: last complete week")
    weekly.add_argument("--out-dir", type=Path, default=DEFAULT_DIR)
    weekly.add_argument("--notify", action="store_true", help="send a short summary to ntfy")
    args = parser.parse_args(argv)

    week = Week.parse(args.week) if args.week else Week.last_complete(datetime.now(UTC))

    from honeypot_ai.db import session_factory

    topic = os.getenv("NTFY_TOPIC", "")
    if args.notify and not topic:
        print("NTFY_TOPIC is not set; add it to .env.", file=sys.stderr)
        return 2

    with session_factory()() as db:
        data = gather(db, week)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out = args.out_dir / f"weekly-{week.label}.md"
    out.write_text(render(data), encoding="utf-8")
    print(f"Written {out}")

    if args.notify:
        from honeypot_ai.health.notify import DEFAULT_SERVER, send

        try:
            send(
                f"Honeypot week {week.label}",
                summary(data) + f"\nFull report: {out}",
                "default",
                topic=topic,
                server=os.getenv("NTFY_SERVER", DEFAULT_SERVER),
                tags="bar_chart",
            )
        except Exception as exc:  # noqa: BLE001 - the report is written; only the ping failed
            print(f"Could not reach ntfy: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
