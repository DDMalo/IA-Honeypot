"""Command-line entry point for enrichment.

    python -m honeypot_ai.enrich

Safe to re-run: addresses already looked up are skipped.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from honeypot_ai.db import session_factory
from honeypot_ai.enrich.geoip import GeoLite2Locator
from honeypot_ai.enrich.worker import DEFAULT_BATCH_SIZE, enrich_pending

DEFAULT_GEOIP_DIR = "/srv/honeypot/geoip"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m honeypot_ai.enrich",
        description="Look up country and network for addresses seen by the honeypot.",
    )
    parser.add_argument(
        "--geoip-dir",
        type=Path,
        default=Path(os.getenv("GEOIP_DIR", DEFAULT_GEOIP_DIR)),
        help=f"directory holding the GeoLite2 .mmdb files (default: {DEFAULT_GEOIP_DIR})",
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="resolve at most this many addresses"
    )
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )

    with GeoLite2Locator(args.geoip_dir) as locator:
        if not locator.available:
            print(
                f"No GeoLite2 databases in {args.geoip_dir}. "
                "See deploy/homelab/README.md for how to fetch them.",
                file=sys.stderr,
            )
            return 2

        with session_factory()() as db:
            stats = enrich_pending(db, locator, args.limit, args.batch_size)

    print(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
