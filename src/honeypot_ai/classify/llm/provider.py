"""The contract every language model backend has to meet.

Deliberately tiny: a name, and a function from two strings to one string.
Everything that makes providers differ — authentication, retries at the HTTP
layer, streaming, token accounting — lives behind it.

That narrowness is what makes the comparison in v0.5.0 mean anything. Gemini
and a local model will be measured against the same prompt, the same parser
and the same validation, so a difference in the numbers is a difference
between the models rather than between two integrations that happened to be
written on different days.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable


class ProviderError(RuntimeError):
    """The backend could not be reached, or refused the request."""


@runtime_checkable
class Provider(Protocol):
    """Something that can answer a prompt with text."""

    @property
    def name(self) -> str:
        """Identifies this backend in stored results. Must be stable."""
        ...

    def complete(self, system: str, user: str) -> str:
        """Return the model's raw reply, or raise `ProviderError`."""
        ...


class StubProvider:
    """A provider that replays canned replies, for tests.

    Exists so the classifier — parsing, validation, retries, fallback — can be
    tested exhaustively without a key, a network, or the non-determinism of a
    real model. The malformed and hostile replies a real model might produce
    once in a thousand calls can be produced here every time.
    """

    def __init__(self, *replies: str | Exception, name: str = "stub") -> None:
        self._replies = list(replies)
        self._name = name
        self.calls: list[tuple[str, str]] = []

    @property
    def name(self) -> str:
        return self._name

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if not self._replies:
            raise ProviderError("StubProvider ran out of replies")
        reply = self._replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


class CallableProvider:
    """Wraps a plain function as a provider, for one-off experiments."""

    def __init__(self, function: Callable[[str, str], str], name: str) -> None:
        self._function = function
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def complete(self, system: str, user: str) -> str:
        return self._function(system, user)
