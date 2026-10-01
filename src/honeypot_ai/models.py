"""Data models for Cowrie events and the sessions assembled from them.

Cowrie writes one JSON object per line, each describing a single thing that
happened: a connection opening, a password being tried, a command being run.
A *session* is the unit this project actually reasons about, so raw events are
parsed into `CowrieEvent` and then aggregated into `Session`.

Two decisions are worth stating up front:

* `CowrieEvent` tolerates unknown fields. Cowrie adds event types over time and
  a new one must never break ingestion of the rest.
* Nothing here trusts its input. Every string in these models was written by an
  attacker, and several fields end up inside an LLM prompt later on.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventId(StrEnum):
    """Cowrie event types this project acts on.

    Any other value is kept verbatim on the event and ignored by the
    aggregator, so unrecognised events are preserved rather than dropped.
    """

    SESSION_CONNECT = "cowrie.session.connect"
    SESSION_CLOSED = "cowrie.session.closed"
    SESSION_PARAMS = "cowrie.session.params"
    CLIENT_VERSION = "cowrie.client.version"
    CLIENT_SIZE = "cowrie.client.size"
    LOGIN_SUCCESS = "cowrie.login.success"
    LOGIN_FAILED = "cowrie.login.failed"
    COMMAND_INPUT = "cowrie.command.input"
    COMMAND_FAILED = "cowrie.command.failed"
    FILE_DOWNLOAD = "cowrie.session.file_download"
    FILE_UPLOAD = "cowrie.session.file_upload"
    DIRECT_TCPIP = "cowrie.direct-tcpip.request"


class Protocol(StrEnum):
    SSH = "ssh"
    TELNET = "telnet"


class CowrieEvent(BaseModel):
    """One line of `cowrie.json`.

    Only the fields shared across event types are declared; everything else is
    retained because Cowrie's schema varies per event and new fields appear
    between releases.
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    eventid: str
    timestamp: datetime
    session: str
    src_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    protocol: Protocol | None = None
    sensor: str = ""
    message: str = ""

    # Present on login events.
    username: str | None = None
    password: str | None = None

    # Present on command events.
    input: str | None = None

    # Present on file transfer events.
    url: str | None = None
    shasum: str | None = None

    # Present on cowrie.client.version.
    version: str | None = None

    # Present on cowrie.session.closed.
    duration: float | None = None

    @field_validator("eventid")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("eventid must not be empty")
        return value

    @property
    def known_event(self) -> EventId | None:
        """The typed event id, or None for event types this project ignores."""
        try:
            return EventId(self.eventid)
        except ValueError:
            return None


class LoginAttempt(BaseModel):
    """A single credential pair tried against the honeypot."""

    model_config = ConfigDict(frozen=True)

    username: str
    password: str
    succeeded: bool
    timestamp: datetime


class Command(BaseModel):
    """A command the attacker typed into the emulated shell.

    `failed` marks commands Cowrie does not emulate; those are interesting in
    their own right, because they reveal what the attacker expected to find.
    """

    model_config = ConfigDict(frozen=True)

    input: str
    failed: bool
    timestamp: datetime


class FileTransfer(BaseModel):
    """A file an attacker tried to fetch, or uploaded.

    Egress is blocked on the sensor, so downloads normally fail — but the URL
    is recorded regardless, which is the part that matters for analysis. Only
    the hash of any captured file is kept; samples never leave the sensor.
    """

    model_config = ConfigDict(frozen=True)

    url: str | None
    shasum: str | None
    uploaded: bool
    timestamp: datetime


class Session(BaseModel):
    """Everything one attacker did in one connection."""

    model_config = ConfigDict(frozen=True)

    session_id: str
    src_ip: str
    src_port: int | None = None
    protocol: Protocol | None = None
    sensor: str = ""
    client_version: str | None = None

    started_at: datetime
    ended_at: datetime | None = None
    duration_seconds: float | None = None

    login_attempts: tuple[LoginAttempt, ...] = Field(default_factory=tuple)
    commands: tuple[Command, ...] = Field(default_factory=tuple)
    file_transfers: tuple[FileTransfer, ...] = Field(default_factory=tuple)

    @property
    def authenticated(self) -> bool:
        """Whether any credential pair was accepted."""
        return any(attempt.succeeded for attempt in self.login_attempts)

    @property
    def interactive(self) -> bool:
        """Whether the attacker ran anything after logging in.

        The distinction matters: most traffic is credential stuffing that never
        gets this far, and sessions that do are the ones worth classifying.
        """
        return bool(self.commands)

    def summary(self) -> dict[str, Any]:
        """Compact description, for logs and quick inspection."""
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "protocol": self.protocol.value if self.protocol else None,
            "login_attempts": len(self.login_attempts),
            "authenticated": self.authenticated,
            "commands": len(self.commands),
            "file_transfers": len(self.file_transfers),
            "duration_seconds": self.duration_seconds,
        }
