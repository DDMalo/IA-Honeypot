"""Command-line entry point for retention.

    python -m honeypot_ai.retention --dry-run
    python -m honeypot_ai.retention

Deleting data cannot be undone, so the dry run exists and the default window
is deliberately generous.
"""

from __future__ import annotations

import argparse
import logging

from honeypot_ai.db import session_factory
from honeypot_ai.retention.policy import DEFAULT_SESSION_DAYS, apply_retention


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.retention",
        description="Delete sessions older than the retention window, and the addresses "
        "no session refers to any more.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_SESSION_DAYS,
        help=f"keep sessions from the last N days (default: {DEFAULT_SESSION_DAYS})",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="report what would be deleted and stop"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    with session_factory()() as db:
        stats = apply_retention(db, args.days, args.dry_run)

    prefix = "Would delete" if args.dry_run else "Deleted"
    print(f"{prefix}: {stats.sessions_deleted} sessions, {stats.addresses_deleted} addresses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
