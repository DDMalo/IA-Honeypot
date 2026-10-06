"""Turning a model's reply into a label, or admitting that it could not.

The contract is that this never raises and never guesses. A model that returns
prose, invalid JSON, an invented intent or nothing at all produces a label of
`other` with a note saying what went wrong — which is a real finding about
that model, and will show up in the v0.5.0 comparison as the failure rate it
deserves rather than disappearing into an exception somewhere.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from honeypot_ai.classify.facts import SessionFacts
from honeypot_ai.classify.llm.prompt import SYSTEM_PROMPT, build_user_prompt
from honeypot_ai.classify.llm.provider import Provider, ProviderError
from honeypot_ai.classify.llm.schema import SessionClassification
from honeypot_ai.classify.taxonomy import Intent, Label, Operator

logger = logging.getLogger(__name__)

#: Models wrap JSON in prose or fences often enough that refusing to look is
#: pedantry. Finding the object is allowed; repairing it is not.
_FENCED = re.compile(r"```(?:json)?\s*(.+?)\s*```", re.DOTALL)
_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


class ParseError(ValueError):
    """The reply could not be read as a classification."""


def extract_json(reply: str) -> dict[str, Any]:
    """Pull the JSON object out of a reply.

    Tolerant about packaging — a fenced block, or an object with chatter
    around it — and strict about content. Nothing here fixes malformed JSON or
    fills in missing fields: a model that cannot produce the requested shape
    should be recorded as having failed, not quietly helped.
    """
    candidate = reply.strip()

    fenced = _FENCED.search(candidate)
    if fenced:
        candidate = fenced.group(1).strip()
    else:
        found = _OBJECT.search(candidate)
        if found:
            candidate = found.group(0)

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise ParseError(f"reply was not JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ParseError(f"reply was {type(parsed).__name__}, not an object")

    return parsed


@dataclass
class LlmStats:
    """How a run went. The failure counts are results, not noise."""

    classified: int = 0
    retried: int = 0
    unparseable: int = 0
    invalid: int = 0
    unavailable: int = 0

    def __str__(self) -> str:
        return (
            f"{self.classified} classified, {self.retried} retried, "
            f"{self.unparseable} unparseable, {self.invalid} invalid, "
            f"{self.unavailable} provider errors"
        )


@dataclass
class LlmClassifier:
    """Classifies sessions through a language model.

    `attempts` is small on purpose. A model that fails the schema twice on the
    same input is usually going to keep failing, and spending ten calls hiding
    that would make the comparison flattering rather than accurate.
    """

    provider: Provider
    attempts: int = 2
    stats: LlmStats = field(default_factory=LlmStats)

    def classify(self, facts: SessionFacts) -> Label:
        """Label one session. Never raises."""
        user_prompt = build_user_prompt(facts)
        last_problem = "no attempt was made"

        for attempt in range(1, self.attempts + 1):
            if attempt > 1:
                self.stats.retried += 1

            try:
                reply = self.provider.complete(SYSTEM_PROMPT, user_prompt)
            except ProviderError as exc:
                last_problem = f"provider unavailable: {exc}"
                logger.warning("%s on %s", last_problem, facts.session_id)
                self.stats.unavailable += 1
                continue

            try:
                payload = extract_json(reply)
            except ParseError as exc:
                last_problem = str(exc)
                logger.warning("Unparseable reply for %s: %s", facts.session_id, exc)
                self.stats.unparseable += 1
                continue

            try:
                classification = SessionClassification.model_validate(payload)
            except ValidationError as exc:
                last_problem = _summarise(exc)
                logger.warning("Invalid classification for %s: %s", facts.session_id, last_problem)
                self.stats.invalid += 1
                continue

            self.stats.classified += 1
            return classification.to_label(facts.session_id)

        return self.unclassified(facts.session_id, last_problem)

    @staticmethod
    def unclassified(session_id: str, reason: str) -> Label:
        """The label a failure produces.

        `other` with zero confidence, which is honest in both directions: the
        session was not classified, and nothing pretends otherwise.
        """
        return Label(
            session_id=session_id,
            intent=Intent.OTHER,
            behaviours=frozenset(),
            operator=Operator.UNKNOWN,
            confidence=0.0,
            notes=f"unclassified: {reason}",
        )


def _summarise(error: ValidationError) -> str:
    """One readable line from a Pydantic error, for the note on the label."""
    problems = [
        f"{'.'.join(str(part) for part in item['loc']) or 'body'}: {item['msg']}"
        for item in error.errors()[:3]
    ]
    return "; ".join(problems)
