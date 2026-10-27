"""The shape a model's answer must take, and what happens when it does not.

Validation here is a security control, not a convenience. The text being
classified was written by people actively trying to subvert a machine, and
some of them write for whatever reads the logs afterwards. A model that has
been talked into answering something else must fail to parse rather than
quietly become the answer.

Three rules make that so:

* `extra="forbid"` — a reply carrying fields nobody asked for is rejected
  whole, rather than silently ignoring the extras.
* Every label is an enum from the taxonomy. A model that invents
  `intent: "ransomware"` fails validation; it cannot widen the vocabulary by
  asserting a new word.
* `rationale` is free text and therefore attacker-influenced. It is length
  capped and stripped of control characters, and nothing downstream may treat
  it as anything but a string to display.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from honeypot_ai.classify.taxonomy import Behaviour, Intent, Label, Operator

MAX_RATIONALE_CHARS = 400

#: Whole ANSI sequences first, then any control byte left over. Order matters:
#: dropping the ESC on its own would leave `[2J` as visible litter.
_ANSI_SEQUENCE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class SessionClassification(BaseModel):
    """One model's answer about one session."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    intent: Intent
    behaviours: tuple[Behaviour, ...] = ()
    operator: Operator = Operator.UNKNOWN
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""

    @field_validator("rationale")
    @classmethod
    def _clean_rationale(cls, value: str) -> str:
        """Strip control characters and cap the length.

        This string is written by a model that has just read attacker-authored
        text. Terminal escape sequences in it would be rendered by whatever
        prints it, so they do not survive this far.
        """
        cleaned = _CONTROL_CHARACTERS.sub("", _ANSI_SEQUENCE.sub("", value)).strip()
        return cleaned[:MAX_RATIONALE_CHARS]

    def to_label(self, session_id: str) -> Label:
        """Convert to the project's own label type.

        Deliberately a separate step: a `SessionClassification` is what a model
        said, a `Label` is what the project records, and keeping the types
        apart means the boundary where untrusted output becomes project data
        is one visible line of code rather than an assumption.
        """
        return Label(
            session_id=session_id,
            intent=self.intent,
            behaviours=frozenset(self.behaviours),
            operator=self.operator,
            confidence=self.confidence,
            notes=self.rationale or None,
        )
