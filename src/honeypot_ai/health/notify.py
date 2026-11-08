"""Tell a person, once, when the verdict changes.

Notifications go through [ntfy](https://ntfy.sh): an HTTP POST to a topic, and
the ntfy app on a phone shows it. No account and no SDK. The topic name is
the only thing standing between the messages and anyone who guesses it, so it
lives in `.env` as a long random string and the messages carry nothing worth
reading to a stranger anyway — counts and times, never an address or a
command.

**Only on change.** The check runs every hour. Paging every hour about the
same broken timer trains a person to mute the app, and then the next failure
is missed too. So the last verdict is kept in a small state file, and a
message goes out when a check starts failing and again when it recovers.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Sequence
from pathlib import Path

import httpx

from honeypot_ai.health.checks import Check

logger = logging.getLogger(__name__)

DEFAULT_SERVER = "https://ntfy.sh"


def default_state_file() -> Path:
    base = os.getenv("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "honeypot-ai" / "health.json"


def read_failing(path: Path) -> set[str]:
    """Names of the checks that were failing last time. Empty if unknown."""
    try:
        return set(json.loads(path.read_text(encoding="utf-8")).get("failing", []))
    except (OSError, ValueError):
        return set()


def write_failing(path: Path, failing: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"failing": sorted(failing)}) + "\n", encoding="utf-8")


def changes(checks: Sequence[Check], previously: set[str]) -> tuple[list[Check], list[Check]]:
    """Checks that started failing, and checks that recovered, since last time."""
    broke = [c for c in checks if not c.ok and c.name not in previously]
    recovered = [c for c in checks if c.ok and c.name in previously]
    return broke, recovered


def message(broke: Sequence[Check], recovered: Sequence[Check]) -> tuple[str, str, str]:
    """Title, body and ntfy priority for one notification."""
    lines = [f"FAIL {c.name}: {c.detail}" for c in broke]
    lines += [f"ok   {c.name}: {c.detail}" for c in recovered]
    if broke:
        names = ", ".join(c.name for c in broke)
        return f"Honeypot: {names} stopped", "\n".join(lines), "high"
    names = ", ".join(c.name for c in recovered)
    return f"Honeypot: {names} recovered", "\n".join(lines), "default"


def send(
    title: str,
    body: str,
    priority: str,
    *,
    topic: str,
    server: str = DEFAULT_SERVER,
    client: httpx.Client | None = None,
    tags: str = "warning",
) -> None:
    """POST one message to ntfy. Raises on failure, so the caller can decide."""
    owned = client is None
    http = client or httpx.Client(timeout=15)
    try:
        response = http.post(
            f"{server.rstrip('/')}/{topic}",
            content=body.encode("utf-8"),
            headers={"Title": title, "Priority": priority, "Tags": tags},
        )
        response.raise_for_status()
    finally:
        if owned:
            http.close()


def notify_on_change(
    checks: Sequence[Check],
    state_file: Path,
    *,
    topic: str,
    server: str = DEFAULT_SERVER,
    client: httpx.Client | None = None,
) -> bool:
    """Send a message if the set of failing checks changed. True if one was sent.

    The state is saved only after the message went out. If ntfy is unreachable
    the change is still pending, and the next hourly run tries again instead
    of the failure being recorded as already reported.
    """
    previously = read_failing(state_file)
    broke, recovered = changes(checks, previously)
    if not broke and not recovered:
        return False
    title, body, priority = message(broke, recovered)
    send(title, body, priority, topic=topic, server=server, client=client)
    write_failing(state_file, {c.name for c in checks if not c.ok})
    return True
