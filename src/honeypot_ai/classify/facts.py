"""What a classifier is allowed to see about a session.

Both classifiers — the rule engine here and the language model in the next
cards — take this and nothing else. That is deliberate on three counts.

**They see the same input.** Comparing a rule engine against a model is only
meaningful if neither has access the other lacks, and a shared, explicit input
type is the cheapest way to guarantee it.

**Neither touches the database.** Classification becomes a pure function of
its input, which is what makes it testable without a server and reproducible
from a stored fixture.

**The source address is absent.** Country, network and reputation are known by
this point and would certainly improve a classifier's apparent accuracy — and
that is precisely why they are excluded. A model that learns "addresses in
this ASN are malicious" has learned about the address, not about the session,
and would rate a session by who sent it rather than by what it did. The whole
question this project asks is what the *behaviour* reveals.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from honeypot_ai.db import SessionRow
from honeypot_ai.models import Session


@dataclass(frozen=True)
class SessionFacts:
    """One session, reduced to what classification may use."""

    session_id: str
    commands: tuple[str, ...] = ()
    authenticated: bool = False
    download_urls: tuple[str, ...] = ()
    captured_hashes: tuple[str, ...] = ()

    #: Seconds between consecutive commands. Used only to tell "certainly a
    #: script" from "cannot tell"; see `rules.infer_operator`.
    command_gaps: tuple[float, ...] = field(default_factory=tuple)

    @property
    def text(self) -> str:
        """Every command as one lowercased blob, for whole-session matching."""
        return "\n".join(self.commands).lower()


def facts_from_session(session: Session) -> SessionFacts:
    """Build the classifier's view from a parsed session."""
    commands = tuple(command.input for command in session.commands)

    gaps: list[float] = []
    ordered = sorted(session.commands, key=lambda command: command.timestamp)
    for earlier, later in zip(ordered, ordered[1:], strict=False):
        gaps.append((later.timestamp - earlier.timestamp).total_seconds())

    return SessionFacts(
        session_id=session.session_id,
        commands=commands,
        authenticated=any(attempt.succeeded for attempt in session.login_attempts),
        download_urls=tuple(
            transfer.url for transfer in session.file_transfers if transfer.url is not None
        ),
        captured_hashes=tuple(
            transfer.shasum for transfer in session.file_transfers if transfer.shasum is not None
        ),
        command_gaps=tuple(gaps),
    )


def facts_from_row(row: SessionRow) -> SessionFacts:
    """Build the classifier's view from a stored session.

    The adapter lives here rather than in the rule engine so that both
    classifiers, and the labelling tool, load sessions the same way — and so
    that a change to the schema has one place to break.
    """
    ordered = sorted(row.commands, key=lambda command: command.occurred_at)

    gaps = [
        (later.occurred_at - earlier.occurred_at).total_seconds()
        for earlier, later in zip(ordered, ordered[1:], strict=False)
    ]

    return SessionFacts(
        session_id=row.session_id,
        commands=tuple(command.input for command in ordered),
        authenticated=row.authenticated,
        download_urls=tuple(
            transfer.url for transfer in row.file_transfers if transfer.url is not None
        ),
        captured_hashes=tuple(
            transfer.shasum for transfer in row.file_transfers if transfer.shasum is not None
        ),
        command_gaps=tuple(gaps),
    )
