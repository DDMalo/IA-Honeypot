"""Check that the pipeline is still producing fresh data.

    python -m honeypot_ai.health              # print the verdict
    python -m honeypot_ai.health --notify     # and tell ntfy when it changes

Exits 1 when any check fails, so the systemd unit shows as failed in
`systemctl --failed` as well as on the phone.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from honeypot_ai.health.checks import LLM_MAX_AGE, RULES_MAX_LAG, SESSIONS_MAX_AGE, run_checks
from honeypot_ai.health.notify import DEFAULT_SERVER, default_state_file, notify_on_change


def _hours(value: str) -> timedelta:
    return timedelta(hours=float(value))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m honeypot_ai.health")
    parser.add_argument("--notify", action="store_true", help="send ntfy messages on change")
    parser.add_argument("--no-llm", action="store_true", help="skip the language-model check")
    parser.add_argument("--sessions-hours", type=_hours, default=SESSIONS_MAX_AGE)
    parser.add_argument("--rules-hours", type=_hours, default=RULES_MAX_LAG)
    parser.add_argument("--llm-hours", type=_hours, default=LLM_MAX_AGE)
    parser.add_argument("--state-file", type=Path, default=None)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    topic = os.getenv("NTFY_TOPIC", "")
    if args.notify and not topic:
        print("NTFY_TOPIC is not set; add it to .env.", file=sys.stderr)
        return 2

    from honeypot_ai.db import session_factory

    with session_factory()() as db:
        checks = run_checks(
            db,
            datetime.now(UTC),
            sessions_max_age=args.sessions_hours,
            rules_max_lag=args.rules_hours,
            llm_max_age=args.llm_hours,
            llm=not args.no_llm,
        )

    for check in checks:
        print(check)

    if args.notify:
        state = args.state_file or default_state_file()
        server = os.getenv("NTFY_SERVER", DEFAULT_SERVER)
        try:
            if notify_on_change(checks, state, topic=topic, server=server):
                print("Notification sent.")
        except Exception as exc:  # noqa: BLE001 - reported, and retried next run
            print(f"Could not reach ntfy: {exc}. Will retry on the next run.", file=sys.stderr)

    return 0 if all(check.ok for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
