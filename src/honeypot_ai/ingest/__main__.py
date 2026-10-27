"""Command-line entry point for ingestion.

    python -m honeypot_ai.ingest /srv/honeypot/raw/cowrie.json

Running it again over the same file is safe and cheap, which is what lets a
timer call it every few minutes without any bookkeeping.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from honeypot_ai.db import session_factory
from honeypot_ai.ingest.worker import DEFAULT_BATCH_SIZE, ingest_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.ingest",
        description="Load a Cowrie log into the database. Safe to re-run.",
    )
    parser.add_argument("log", type=Path, help="path to cowrie.json")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"sessions per transaction (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log every batch")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    if not args.log.is_file():
        print(f"No such file: {args.log}", file=sys.stderr)
        return 2

    with session_factory()() as db:
        stats = ingest_file(db, args.log, args.batch_size)

    if stats.parse is not None and stats.parse.skipped:
        print(
            f"Warning: skipped {stats.parse.skipped} unreadable lines "
            f"({stats.parse.malformed} malformed, {stats.parse.invalid} invalid)",
            file=sys.stderr,
        )

    print(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
