"""Command-line entry point for reputation lookups.

    python -m honeypot_ai.reputation --dry-run
    python -m honeypot_ai.reputation

Safe to re-run: addresses checked recently are skipped, so a second run in the
same day costs nothing. The dry run exists because every real run spends part
of a daily allowance that cannot be bought back.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from honeypot_ai.db import session_factory
from honeypot_ai.reputation.abuseipdb import (
    DEFAULT_MAX_AGE_IN_DAYS,
    DEFAULT_MIN_INTERVAL,
    AbuseIpdbClient,
    ReputationError,
)
from honeypot_ai.reputation.worker import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_DAILY_LIMIT,
    DEFAULT_MAX_AGE_DAYS,
    check_addresses,
    pending_addresses,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.reputation",
        description="Look up the reputation of addresses seen by the honeypot.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_DAILY_LIMIT,
        help=f"check at most this many addresses (default: {DEFAULT_DAILY_LIMIT})",
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"re-check an address after this long (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    parser.add_argument(
        "--report-window",
        type=int,
        default=DEFAULT_MAX_AGE_IN_DAYS,
        help=f"how far back AbuseIPDB counts reports (default: {DEFAULT_MAX_AGE_IN_DAYS})",
    )
    parser.add_argument("--min-interval", type=float, default=DEFAULT_MIN_INTERVAL)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report how many addresses are due and stop, without spending any quota",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    with session_factory()() as db:
        addresses = pending_addresses(db, args.limit, args.max_age_days)

        if args.dry_run:
            print(f"{len(addresses)} addresses are due a reputation check")
            return 0

        if not addresses:
            print("Nothing to check")
            return 0

        try:
            with AbuseIpdbClient(
                api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
                max_age_in_days=args.report_window,
                min_interval=args.min_interval,
            ) as client:
                stats = check_addresses(db, client, addresses, args.batch_size)
                remaining = client.remaining
        except ReputationError as exc:
            print(exc, file=sys.stderr)
            return 2

    if remaining is not None:
        print(f"{stats} — {remaining} checks left today")
    else:
        print(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
